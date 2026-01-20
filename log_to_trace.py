#!/usr/bin/env python3
"""
log_to_trace.py - Log file to OpenTelemetry traces converter

Reads a log file containing scrubber state information and outputs
OpenTelemetry traces in JSON format compatible with Jaeger.
"""

import re
import json
import sys
import uuid
import time
import os
import subprocess
import datetime
import tempfile
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field


class ReferenceType(str, Enum):
    """OpenTelemetry/Jaeger reference types."""
    CHILD_OF = "CHILD_OF"
    FOLLOWS_FROM = "FOLLOWS_FROM"

# Canonical state names
CANONICAL_STATES = [
    "NotActive",
    "PrimaryActive",
    "PrimaryActive/PrimaryIdle",
    "PrimaryActive/Session",
    "PrimaryActive/Session/ReservingReplicas",
    "PrimaryActive/Session/ActiveScrubbing",
    "PrimaryActive/Session/ActiveScrubbing/PendingTimer",
    "PrimaryActive/Session/ActiveScrubbing/RangeBlocked",
    "PrimaryActive/Session/ActiveScrubbing/NewChunk",
    "PrimaryActive/Session/ActiveScrubbing/WaitPushes",
    "PrimaryActive/Session/ActiveScrubbing/WaitLastUpdate",
    "PrimaryActive/Session/ActiveScrubbing/BuildMap",
    "PrimaryActive/Session/ActiveScrubbing/DrainReplMaps",
    "PrimaryActive/Session/ActiveScrubbing/WaitReplicas",
    "PrimaryActive/Session/ActiveScrubbing/WaitDigestUpdate",
    "ReplicaActive",
    "ReplicaActive/ReplicaIdle",
    "ReplicaActive/ReplicaActiveOp",
    "ReplicaActive/ReplicaActiveOp/ReplicaWaitUpdates",
    "ReplicaActive/ReplicaActiveOp/ReplicaBuildingMap",
]

# States that trigger trace reset and don't create spans
RESET_STATES = {"NotActive", "PrimaryActive/PrimaryIdle", "ReplicaActive", "ReplicaActive/ReplicaIdle"}


@dataclass
class Span:
    """Represents an OpenTelemetry span."""
    trace_id: str
    span_id: str
    parent_span_id: Optional[str]
    name: str
    state_name: str
    start_time_ns: int
    end_time_ns: Optional[int] = None
    attributes: Dict[str, Any] = field(default_factory=dict)
    # optional follows-from link span id (used for replica spans)
    follows_from_span_id: Optional[str] = None


@dataclass
class SpanStackEntry:
    """Entry in the span stack."""
    state_name: str
    span: Span


def generate_trace_id() -> str:
    """Generate a 32-character hex trace ID."""
    return uuid.uuid4().hex


def generate_span_id() -> str:
    """Generate a 16-character hex span ID."""
    return uuid.uuid4().hex[:16]


def parse_iso_to_ns(ts: Optional[str]) -> Optional[int]:
    """Parse an ISO-like timestamp string and return nanoseconds since epoch.

    Accepts timestamps like '2026-01-14T16:28:46.274+0000' or with no timezone.
    If parsing fails, returns None.
    """
    if not ts:
        return None
    try:
        # Normalize timezone like +0000 to +00:00 for fromisoformat
        s = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', ts)
        # datetime.fromisoformat supports the normalized form
        dt = datetime.datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp() * 1e9)
    except Exception:
        return None


def normalize_pg_id(pg_id: str) -> str:
    """Normalize PG ID by removing the optional 's' suffix."""
    match = re.match(r'^(\d+\.[0-9a-f]+)', pg_id, re.IGNORECASE)
    if match:
        return match.group(1)
    return pg_id


def translate_state_name(state_name: str) -> str:
    """Translate 'Act' to 'ActiveScrubbing' in state names."""
    parts = state_name.split('/')
    translated = []
    for part in parts:
        if part == 'Act':
            translated.append('ActiveScrubbing')
        else:
            translated.append(part)
    return '/'.join(translated)


def resolve_canonical_state(partial_state: str) -> Optional[str]:
    """
    Resolve a possibly partial state name to its canonical form.
    The partial state may be a postfix of a canonical state.
    """
    # First translate 'Act' to 'ActiveScrubbing'
    translated = translate_state_name(partial_state)

    # Check if it's already a canonical state
    if translated in CANONICAL_STATES:
        return translated

    # Try to find a canonical state that ends with this partial state
    for canonical in CANONICAL_STATES:
        if canonical.endswith('/' + translated):
            return canonical

    return None


def is_substate_of(state: str, potential_parent: str) -> bool:
    """Check if state is a direct sub-state of potential_parent."""
    if state == potential_parent:
        return False
    # Check if state starts with potential_parent/ and has exactly one more component
    if state.startswith(potential_parent + '/'):
        remainder = state[len(potential_parent) + 1:]
        return '/' not in remainder
    return False


def is_superstate_of(state: str, potential_child: str) -> bool:
    """Check if state is a super-state of potential_child."""
    return potential_child.startswith(state + '/')


def get_state_hierarchy(state: str) -> List[str]:
    """Get all states from root to the given state (inclusive)."""
    parts = state.split('/')
    hierarchy = []
    for i in range(1, len(parts) + 1):
        hierarchy.append('/'.join(parts[:i]))
    return hierarchy


def find_common_ancestor(state1: str, state2: str) -> Optional[str]:
    """Find the common ancestor of two states."""
    hierarchy1 = set(get_state_hierarchy(state1))
    hierarchy2 = get_state_hierarchy(state2)

    common = None
    for state in hierarchy2:
        if state in hierarchy1:
            common = state
    return common


class LogParser:
    """Parser for log lines."""

    # Regex patterns
    PG_ID_PATTERN = re.compile(r'pg\[(\d+\.[0-9a-f]+(?:s[0-9a-f]+)?)', re.IGNORECASE)
    STATE_PATTERN = re.compile(r'scrubber<([\w/]+)>')
    SOURCE_OSD_PATTERN = re.compile(r'(osd\.\d+)')
    ACT_SET_PATTERN = re.compile(r'\[(\d+(?:,\d+)*)\]')
    UNLOCKED_PATTERN = re.compile(r'\(unlocked\)')

    def parse_line(self, line: str) -> Optional[Dict[str, Any]]:
        """
        Parse a log line and extract relevant information.
        Returns None if the line should be ignored.
        """
        # Skip lines with '(unlocked)'
        if self.UNLOCKED_PATTERN.search(line):
            return None

        # Extract the original timestamp (first token of the line) if present
        orig_ts = None
        parts = line.split()
        if not parts:
            return None

        orig_ts = parts[0]

        # Extract PG ID
        pg_match = self.PG_ID_PATTERN.search(line)
        if not pg_match:
            return None

        # Extract state name
        state_match = self.STATE_PATTERN.search(line)
        if not state_match:
            return None

        # Extract source OSD
        osd_match = self.SOURCE_OSD_PATTERN.search(line)
        if not osd_match:
            return None

        pg_id_raw = pg_match.group(1)
        pg_id_normalized = normalize_pg_id(pg_id_raw)
        state_name_raw = state_match.group(1)
        source_osd = osd_match.group(1)

        # Resolve canonical state name
        canonical_state = resolve_canonical_state(state_name_raw)
        if canonical_state is None:
            return None

        # Extract act-set if present
        act_set = None
        act_set_match = self.ACT_SET_PATTERN.search(line)
        if act_set_match:
            act_set = [int(x) for x in act_set_match.group(1).split(',')]

        return {
            'pg_id_raw': pg_id_raw,
            'pg_id': pg_id_normalized,
            'state': canonical_state,
            'source_osd': source_osd,
            'act_set': act_set,
            'orig_ts': orig_ts,
        }


class TraceBuilder:
    """Builds OpenTelemetry traces from parsed log data.

    State Machine Behavior:
    ----------------------
    The builder maintains a stack of open spans for each (pg_id, source_osd).

    State Transitions:
    - S_new == S_old: No-op (same state)
    - S_old is prefix of S_new: Create child/intermediate spans
    - Otherwise: Pop stack until common ancestor, then build to S_new

    Reset States:
    - NotActive, PrimaryActive/PrimaryIdle, ReplicaActive, ReplicaActive/ReplicaIdle
    - These close all spans and start new traces

    Linking:
    - Replica spans (ReplicaActive/ReplicaActiveOp) link to primary spans via FOLLOWS_FROM
    """

    def __init__(self, debug: bool = False):
        # trace_id per normalized PG ID
        self.trace_ids: Dict[str, str] = {}
        # Last seen act-set per normalized PG ID
        self.act_sets: Dict[str, List[int]] = {}
        # Span stack per (pg_id, source_osd)
        self.span_stacks: Dict[Tuple[str, str], List[SpanStackEntry]] = {}
        # Previous state per (pg_id, source_osd)
        self.prev_states: Dict[Tuple[str, str], str] = {}
        # All completed spans
        self.completed_spans: List[Span] = []
        # Current timestamp counter (simulated)
        self.current_time_ns = int(time.time() * 1_000_000_000)
        # Last processed line original timestamp string (first token)
        self.last_line_ts: Optional[str] = None
        # Track last primary span object per PG ID (persist even after span closed)
        self.last_primary_span: Dict[str, Span] = {}
        self.last_primary_span_id: Dict[str, str] = {}
        # Setup logger (level controlled via --debug CLI flag)
        import logging
        self.logger = logging.getLogger('log_to_trace')
        if debug:
            logging.basicConfig(level=logging.DEBUG)
            self.logger.setLevel(logging.DEBUG)
        else:
            logging.basicConfig(level=logging.INFO)
            self.logger.setLevel(logging.INFO)

    def get_trace_id(self, pg_id: str) -> str:
        """Get or create a trace ID for a PG ID."""
        if pg_id not in self.trace_ids:
            self.trace_ids[pg_id] = generate_trace_id()
        return self.trace_ids[pg_id]

    def new_trace_id(self, pg_id: str) -> str:
        """Create a new trace ID for a PG ID."""
        self.trace_ids[pg_id] = generate_trace_id()
        return self.trace_ids[pg_id]

    def _determine_role(self, source_osd: str, act_set: Optional[List[int]], state: str) -> str:
        """Determine if the source OSD is primary or replica."""
        if act_set:
            osd_num = int(source_osd.split('.')[1])
            return 'primary' if act_set[0] == osd_num else 'replica'
        # Fallback: infer from state name
        return 'primary' if state.startswith('PrimaryActive') else 'replica'

    def _get_start_time(self, line_ts: Optional[str]) -> int:
        """Get start time in nanoseconds, updating current time if needed."""
        parsed_ns = parse_iso_to_ns(line_ts) if line_ts else None
        start_ns = parsed_ns if parsed_ns is not None else self.current_time_ns
        if start_ns > self.current_time_ns:
            self.current_time_ns = start_ns
        return start_ns

    def _determine_linking(self, pg_id: str, role: str, state: str,
                           act_set: Optional[List[int]]) -> Tuple[Optional[str], Optional[str]]:
        """Determine linking for replica spans. Returns (span_id, trace_id)."""
        if role != 'replica' or state != 'ReplicaActive/ReplicaActiveOp':
            return None, None

        # Try to link to primary span
        act = act_set if act_set is not None else self.act_sets.get(pg_id)
        if act and len(act) > 0:
            primary_osd = f"osd.{act[0]}"
            primary_key = (pg_id, primary_osd)

            # Prefer linking to the last PrimaryActive/Session span for the primary OSD
            primary_stack = self.span_stacks.get(primary_key)
            if primary_stack:
                for entry in reversed(primary_stack):
                    if entry.span.state_name == "PrimaryActive/Session":
                        primary_span = entry.span
                        self.logger.debug(
                            f"Linking to open primary session span {primary_span.span_id}"
                        )
                        return primary_span.span_id, primary_span.trace_id

            primary_osd_id = primary_osd.split(".")[-1]
            for span in reversed(self.completed_spans):
                if (
                    span.state_name == "PrimaryActive/Session"
                    and span.attributes.get("role") == "primary"
                    and span.attributes.get("osd.source") == primary_osd_id
                ):
                    self.logger.debug(
                        f"Linking to closed primary session span {span.span_id}"
                    )
                    return span.span_id, span.trace_id

            # Prefer open primary span
            if primary_stack:
                primary_span = primary_stack[-1].span
                self.logger.debug(f"Linking to open primary span {primary_span.span_id}")
                return primary_span.span_id, primary_span.trace_id

        # Fallback to last known primary span
        last_primary = self.last_primary_span.get(pg_id)
        if last_primary:
            self.logger.debug(f"Linking to last primary span {last_primary.span_id}")
            return last_primary.span_id, last_primary.trace_id

        self.logger.debug(f"No primary span available for linking")
        return None, None

    def _build_span(self, pg_id: str, source_osd: str, state: str, role: str,
                    trace_id: str, start_ns: int, parent_span_id: Optional[str],
                    act_set: Optional[List[int]], line_ts: Optional[str],
                    follows_from_span_id: Optional[str]) -> Span:
        """Build the span object with all attributes."""
        span_name = f"{pg_id}_{role}_{state}"
        osd_source = source_osd.split('.')[-1]

        span = Span(
            trace_id=trace_id,
            span_id=generate_span_id(),
            parent_span_id=parent_span_id,
            name=span_name,
            state_name=state,
            start_time_ns=start_ns,
            follows_from_span_id=follows_from_span_id,
            attributes={
                'pg.id': pg_id,
                'state.name': state,
                'act.set': str(act_set) if act_set else '[]',
                'role': role,
                'osd.source': osd_source,
                'start_time_iso': line_ts if line_ts is not None else '',
            }
        )

        self.logger.debug(f"Created span {span.span_id} name={span.name} state={state} role={role}")
        return span

    def create_span(self, pg_id: str, source_osd: str, state: str,
                    act_set: Optional[List[int]], parent_span_id: Optional[str],
                    line_ts: Optional[str] = None) -> Span:
        """Create a new span."""
        role = self._determine_role(source_osd, act_set, state)
        start_ns = self._get_start_time(line_ts)

        # Determine linking for replica spans
        linked_span_id, linked_trace_id = self._determine_linking(pg_id, role, state, act_set)

        # Use linked trace ID if available
        trace_id = linked_trace_id if linked_trace_id else self.get_trace_id(pg_id)
        if linked_trace_id and self.trace_ids.get(pg_id) != linked_trace_id:
            self.logger.debug(f"Updating trace_id for PG {pg_id} to linked trace {linked_trace_id}")
            self.trace_ids[pg_id] = linked_trace_id

        # Create span
        span = self._build_span(pg_id, source_osd, state, role, trace_id,
                               start_ns, parent_span_id, act_set, line_ts, linked_span_id)

        # Track primary spans
        if role == 'primary':
            self.last_primary_span[pg_id] = span
            self.last_primary_span_id[pg_id] = span.span_id
            self.logger.debug(f"Recorded primary span {span.span_id} as last_primary for PG {pg_id}")

        return span

    def close_span(self, span: Span, end_time_iso: Optional[str] = None):
        """Close a span and add it to completed spans."""
        # If an end_time_iso is provided, try to parse it to ns
        parsed_ns = parse_iso_to_ns(end_time_iso) if end_time_iso else None
        if parsed_ns is not None:
            span.end_time_ns = parsed_ns
            # Keep simulated clock monotonic
            if parsed_ns > self.current_time_ns:
                self.current_time_ns = parsed_ns
        else:
            span.end_time_ns = self.current_time_ns

        # Use provided end_time_iso (original log timestamp) if available
        if end_time_iso is not None:
            span.attributes['end_time_iso'] = end_time_iso
        else:
            # Fallback: reuse start_time_iso or empty string
            span.attributes['end_time_iso'] = span.attributes.get('start_time_iso', '')

        self.logger.debug(f"Closed span {span.span_id} name={span.name} end_ns={span.end_time_ns}")
        # If this is a primary span that gets closed, update last_primary_span_id to the closed span
        if span.attributes.get('role') == 'primary':
            self.last_primary_span_id[span.attributes.get('pg.id')] = span.span_id
            self.logger.debug(f"Updated last_primary_span_id for PG {span.attributes.get('pg.id')} to {span.span_id} (closed primary)")

        self.completed_spans.append(span)

    def close_all_spans(self, key: Tuple[str, str], end_time_iso: Optional[str] = None):
        """Close all spans for a given (pg_id, source_osd) combination."""
        if key in self.span_stacks:
            while self.span_stacks[key]:
                entry = self.span_stacks[key].pop()
                self.close_span(entry.span, end_time_iso=end_time_iso)

    def _update_context(self, pg_id: str, act_set: Optional[List[int]], line_ts: Optional[str]):
        """Update tracking context."""
        if act_set is not None:
            self.act_sets[pg_id] = act_set
        self.last_line_ts = line_ts
        self.current_time_ns += 1_000_000  # 1ms increment

    def _handle_reset_state(self, s_new: str, prev_state: Optional[str],
                            key: Tuple[str, str], pg_id: str, line_ts: Optional[str]) -> bool:
        """Handle reset states. Returns True if state was a reset state."""
        if s_new not in RESET_STATES:
            return False

        self.close_all_spans(key, end_time_iso=line_ts)
        self.prev_states[key] = s_new

        if prev_state in RESET_STATES or prev_state is None:
            self.new_trace_id(pg_id)

        return True

    def _ensure_stack(self, key: Tuple[str, str]) -> List[SpanStackEntry]:
        """Ensure span stack exists and return it."""
        if key not in self.span_stacks:
            self.span_stacks[key] = []
        return self.span_stacks[key]

    def _handle_substate_transition(self, stack: List[SpanStackEntry], s_old: str, s_new: str,
                                    pg_id: str, source_osd: str, act_set: Optional[List[int]],
                                    line_ts: Optional[str]):
        """Handle transitions where s_new is a substate of s_old."""
        if is_substate_of(s_new, s_old):
            parent_span_id = stack[-1].span.span_id
            span = self.create_span(pg_id, source_osd, s_new, act_set, parent_span_id, line_ts=line_ts)
            stack.append(SpanStackEntry(state_name=s_new, span=span))
        else:
            self._create_intermediate_spans(stack, s_old, s_new, pg_id, source_osd, act_set, line_ts)

    def _create_intermediate_spans(self, stack: List[SpanStackEntry], s_old: str, s_new: str,
                                   pg_id: str, source_osd: str, act_set: Optional[List[int]],
                                   line_ts: Optional[str]):
        """Create intermediate spans to reach s_new from s_old."""
        target_hierarchy = get_state_hierarchy(s_new)
        current_hierarchy = get_state_hierarchy(s_old)
        start_idx = len(current_hierarchy)

        parent_span_id = stack[-1].span.span_id
        for i in range(start_idx, len(target_hierarchy)):
            intermediate_state = target_hierarchy[i]
            if intermediate_state in RESET_STATES:
                continue
            span = self.create_span(pg_id, source_osd, intermediate_state, act_set, parent_span_id, line_ts=line_ts)
            stack.append(SpanStackEntry(state_name=intermediate_state, span=span))
            parent_span_id = span.span_id

    def _handle_divergent_transition(self, stack: List[SpanStackEntry], s_new: str,
                                     pg_id: str, source_osd: str, act_set: Optional[List[int]],
                                     line_ts: Optional[str]):
        """Handle transitions where s_new diverges from s_old."""
        if not stack:
            self._build_stack_from_root(stack, s_new, pg_id, source_osd, act_set, line_ts)
        else:
            self._close_until_superstate(stack, s_new, line_ts)
            self._extend_stack_to_target(stack, s_new, pg_id, source_osd, act_set, line_ts)

    def _build_stack_from_root(self, stack: List[SpanStackEntry], s_new: str,
                               pg_id: str, source_osd: str, act_set: Optional[List[int]],
                               line_ts: Optional[str]):
        """Build span stack from root to s_new."""
        target_hierarchy = get_state_hierarchy(s_new)
        parent_span_id = None

        for intermediate_state in target_hierarchy:
            if intermediate_state in RESET_STATES:
                continue
            span = self.create_span(pg_id, source_osd, intermediate_state, act_set, parent_span_id, line_ts=line_ts)
            stack.append(SpanStackEntry(state_name=intermediate_state, span=span))
            parent_span_id = span.span_id

    def _close_until_superstate(self, stack: List[SpanStackEntry], s_new: str, line_ts: Optional[str]):
        """Close spans until we find a superstate of s_new."""
        while stack:
            top_state = stack[-1].state_name
            if top_state == s_new or is_superstate_of(top_state, s_new):
                break
            entry = stack.pop()
            self.close_span(entry.span, end_time_iso=line_ts)

    def _extend_stack_to_target(self, stack: List[SpanStackEntry], s_new: str,
                                pg_id: str, source_osd: str, act_set: Optional[List[int]],
                                line_ts: Optional[str]):
        """Extend stack from current state to s_new."""
        if stack:
            current_state = stack[-1].state_name
            parent_span_id = stack[-1].span.span_id
            target_hierarchy = get_state_hierarchy(s_new)
            current_hierarchy = get_state_hierarchy(current_state)
            start_idx = len(current_hierarchy)
        else:
            parent_span_id = None
            target_hierarchy = get_state_hierarchy(s_new)
            start_idx = 0

        for i in range(start_idx, len(target_hierarchy)):
            intermediate_state = target_hierarchy[i]
            if intermediate_state in RESET_STATES:
                continue
            span = self.create_span(pg_id, source_osd, intermediate_state, act_set, parent_span_id, line_ts=line_ts)
            stack.append(SpanStackEntry(state_name=intermediate_state, span=span))
            parent_span_id = span.span_id

    def process_entry(self, data: Dict[str, Any]):
        """Process a parsed log entry."""
        pg_id = data['pg_id']
        s_new = data['state']
        source_osd = data['source_osd']
        act_set = data['act_set']
        line_ts = data.get('orig_ts')
        # the_session = s_new == "PrimaryActive/Session"

        # Update context
        self._update_context(pg_id, act_set, line_ts)
        act_set = act_set if act_set is not None else self.act_sets.get(pg_id)

        key = (pg_id, source_osd)
        prev_state = self.prev_states.get(key)

        # Handle reset states
        if self._handle_reset_state(s_new, prev_state, key, pg_id, line_ts):
            return

        # Check if we need a new trace
        if prev_state in RESET_STATES or prev_state is None:
            self.new_trace_id(pg_id)

        # Initialize stack and get current state
        stack = self._ensure_stack(key)
        s_old = stack[-1].state_name if stack else None

        # Case 1: Same state - no-op
        if s_old and s_new == s_old:
            self.prev_states[key] = s_new
            return

        # Case 2: S_old is a prefix of S_new
        if s_old and s_new.startswith(s_old + '/'):
            self._handle_substate_transition(stack, s_old, s_new, pg_id, source_osd, act_set, line_ts)
        else:
            # Case 3: Divergent transition
            self._handle_divergent_transition(stack, s_new, pg_id, source_osd, act_set, line_ts)

        self.prev_states[key] = s_new



    def finalize(self):
        """Close all remaining open spans."""
        for key in list(self.span_stacks.keys()):
            self.close_all_spans(key, end_time_iso=self.last_line_ts)

    def to_jaeger_format(self) -> Dict[str, Any]:
        """
        Convert completed spans to Jaeger-compatible JSON format.

        Jaeger references format:
        - CHILD_OF: Parent-child relationship (typical hierarchical spans)
        - FOLLOWS_FROM: Causal relationship without strict parent-child semantics

        Both reference types use the same structure:
        {
            "refType": "CHILD_OF" | "FOLLOWS_FROM",
            "traceID": "<trace-id>",
            "spanID": "<referenced-span-id>"
        }
        """
        # Group spans by trace
        traces_by_id: Dict[str, List[Span]] = {}
        for span in self.completed_spans:
            if span.trace_id not in traces_by_id:
                traces_by_id[span.trace_id] = []
            traces_by_id[span.trace_id].append(span)

        # Build Jaeger format
        data = []
        for trace_id, spans in traces_by_id.items():
            trace_data = {
                "traceID": trace_id,
                "spans": [],
                "processes": {
                    "p1": {
                        "serviceName": "ceph-scrubber",
                        "tags": []
                    }
                }
            }

            for span in spans:
                span_data = {
                    "traceID": span.trace_id,
                    "spanID": span.span_id,
                    "operationName": span.name,
                    "references": [],
                    "startTime": span.start_time_ns // 1000,  # Convert to microseconds
                    "duration": ((span.end_time_ns or span.start_time_ns) - span.start_time_ns) // 1000,
                    "tags": [
                        {"key": k, "type": "string", "value": str(v)}
                        for k, v in span.attributes.items()
                        if k != 'opentracing.ref_type' and k != 'opentracing.follows_from'
                    ],
                    "logs": [],
                    "processID": "p1",
                    "warnings": None
                }

                # Add CHILD_OF reference for parent-child relationships
                if span.parent_span_id:
                    span_data["references"].append({
                        "refType": ReferenceType.CHILD_OF.value,
                        "traceID": span.trace_id,
                        "spanID": span.parent_span_id
                    })

                # Add FOLLOWS_FROM reference if present (Jaeger-compatible)
                # This is used for replica spans linking to primary spans
                if span.follows_from_span_id:
                    span_data["references"].append({
                        "refType": ReferenceType.FOLLOWS_FROM.value,
                        "traceID": span.trace_id,
                        "spanID": span.follows_from_span_id
                    })

                trace_data["spans"].append(span_data)

            data.append(trace_data)

        return {"data": data}


@dataclass
class Arguments:
    """Parsed command line arguments."""
    input_files: List[str]
    output_file: Optional[str]
    debug: bool


def parse_arguments() -> Arguments:
    """Parse command line arguments."""
    if len(sys.argv) < 2:
        print("Usage: python3 log_to_trace.py <input-log-file>... [--out=output.json] [--debug]", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]
    input_files: List[str] = []
    output_file: Optional[str] = None
    debug = False

    i = 0
    while i < len(args):
        a = args[i]
        if a.startswith('--out='):
            output_file = a.split('=', 1)[1]
        elif a == '--out':
            if i + 1 >= len(args):
                print("Error: --out requires a filename", file=sys.stderr)
                sys.exit(1)
            output_file = args[i + 1]
            i += 1
        elif a in ('--debug', '-d'):
            debug = True
        else:
            input_files.append(a)
        i += 1

    if not input_files:
        print("Usage: python3 log_to_trace.py <input-log-file>... [--out=output.json] [--debug]", file=sys.stderr)
        sys.exit(1)

    # If no --out specified, create a temporary output file
    if output_file is None:
        tmpf = tempfile.NamedTemporaryFile(prefix='log_to_trace-', suffix='.json', dir='/tmp', delete=False)
        output_file = tmpf.name
        tmpf.close()
        print(f"No --out specified. Writing traces to temporary file {output_file}", file=sys.stderr)

    return Arguments(input_files=input_files, output_file=output_file, debug=debug)


def prepare_input_files(input_files: List[str]) -> List[str]:
    """Prepare and filter input files to temp files.

    Returns list of temporary file paths containing filtered log lines.
    """
    tmp_files: List[str] = []

    for infile in input_files:
        base = os.path.basename(infile)
        tmp_path = f"/tmp/{base}.debug"
        tmp_files.append(tmp_path)

        cat_cmd = ["zcat", infile] if infile.endswith('.gz') else ["cat", infile]
        grep_cmd = ["grep", "-a", "-s", "scrubber<"]

        # Run pipeline and write to tmp_path
        with open(tmp_path, 'wb') as out:
            p1 = subprocess.Popen(cat_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p2 = subprocess.Popen(grep_cmd, stdin=p1.stdout, stdout=out, stderr=subprocess.DEVNULL)
            p1.stdout.close()
            p2.wait()
            p1.wait()

    return tmp_files


def process_sorted_logs(tmp_files: List[str], parser: LogParser, builder: TraceBuilder):
    """Process sorted log lines through parser and builder."""
    sort_cmd = ["sort", "-m", "--stable"] + tmp_files
    env = os.environ.copy()
    env["LC_ALL"] = "C"

    p_sort = subprocess.Popen(sort_cmd, stdout=subprocess.PIPE, env=env, text=True)
    try:
        for line in p_sort.stdout:
            line = line.rstrip('\n')
            if not line:
                continue
            data = parser.parse_line(line)
            if data:
                builder.process_entry(data)
    finally:
        if p_sort.stdout:
            p_sort.stdout.close()
        p_sort.wait()


def write_output(builder: TraceBuilder, output_file: str):
    """Write traces to output file and print summary."""
    builder.finalize()
    output = builder.to_jaeger_format()

    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"Traces written to {output_file}")
    print(f"Total spans: {len(builder.completed_spans)}")
    print(f"Total traces: {len(output['data'])}")


def main():
    """Main entry point.

    Usage: python3 log_to_trace.py <input-log-file>... [--out=output.json] [--debug]

    For each input file:
      - run `zcat <file>` if it ends with .gz, otherwise `cat <file>`
      - pipe to `grep -a -s 'scrubber<'`
      - write filtered lines to /tmp/<basename>.debug
    Then run `LC_ALL=C sort -m --stable /tmp/*.debug` to merge the debug files and stream
    the sorted lines for processing.
    """
    args = parse_arguments()

    if args.debug:
        print("Debug logging enabled", file=sys.stderr)

    # Process input files
    tmp_files = prepare_input_files(args.input_files)

    # Parse and build traces
    parser = LogParser()
    builder = TraceBuilder(debug=args.debug)
    process_sorted_logs(tmp_files, parser, builder)

    # Output results
    write_output(builder, args.output_file)


if __name__ == "__main__":
    main()
