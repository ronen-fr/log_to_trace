"""Package marker for log_to_trace tests.

Expose public symbols used by the tests.
"""

from .log_to_trace import parse_arguments, TraceBuilder

__all__ = ["parse_arguments", "TraceBuilder"]
