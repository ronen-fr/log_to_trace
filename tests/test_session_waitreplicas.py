import json

from log_to_trace import LogParser, TraceBuilder


def _find_span_by_state(spans, state_name):
    for s in spans:
        if s.state_name == state_name:
            return s
    return None


def test_wait_replicas_accumulates_objects_and_evi():
    parser = LogParser()
    b = TraceBuilder(debug=False, fixed=True)

    # Start a Session and transition into WaitReplicas on osd.8, pg 2.2
    lines = [
        "2026-01-21T09:30:48.605+0000 7fe23a4de640 10 osd.8 pg[2.2( v 28'2 (0'0,28'2] local-lis/les=25/26 n=1 ec=25/25 ) [8,7,0] r=0] scrubber<Session/Act/WaitReplicas>: FSM: WaitReplicas::react(const GotReplicas&)",
        # replicas decode_received_map -> should set e_v_i for replica shards 0 and 7
        "2026-01-21T09:30:48.605+0000 7fe23e4e6640 15 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: decode_received_map: decoded map from : 0: versions: 28'2 / 25",
        "2026-01-21T09:30:48.605+0000 7fe23a4de640 15 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: decode_received_map: decoded map from : 7: versions: 28'2 / 25",
        # merge_to_authoritative_set entries for replicas -> objects_count
        "2026-01-21T09:30:48.605+0000 7fe23e4e6640 15 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: merge_to_authoritative_set: replica 0 has 1 items",
        "2026-01-21T09:30:48.605+0000 7fe23a4de640 15 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: merge_to_authoritative_set: replica 7 has 1 items",
        # compare_smaps should set primary's authoritative count and primary e_v_i from 'v'/'local-lis/les' in the PG descriptor
        "2026-01-21T09:30:48.605+0000 7fe23e4e6640 10 osd.8 pg[2.2( v 28'2 (0'0,28'2] local-lis/les=25/26 ) [8,7,0] r=0] scrubber<Session/Act/WaitReplicas>:  b.e.: compare_smaps: authoritative-set #: 1",
        # add some select_auth_object lines — objects should only be captured when objects option is enabled (tested separately)
        "2026-01-21T09:30:48.605+0000 7fe23e4e6640 10 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: select_auth_object: 2:ff7b1f36:::obj1:12 shard 3 got:{shard-usable: ...}",
        "2026-01-21T09:30:48.605+0000 7fe23e4e6640 10 osd.8 pg[2.2(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: select_auth_object: selecting osd 3 for obj 2:ff7b1f36:::obj1:12 with oi ...",
        # move to a reset state to close spans
        "2026-01-21T09:30:49.000+0000 7fe23e4e6640 10 osd.8 pg[2.2(...)] scrubber<NotActive>: FSM: -- state -->> NotActive",
    ]

    for l in lines:
        parsed = parser.parse_line(l)
        if parsed:
            b.process_entry(parsed)

    b.finalize()

    # Attributes should be attached to the enclosing in-chunk span (not the WaitReplicas child)
    in_chunk = _find_span_by_state(b.completed_spans, "PrimaryActive/Session/ActiveScrubbing/in-chunk")
    assert in_chunk is not None, "in-chunk span not found"

    # objects_count should contain primary '8' and replicas '0' and '7'
    objects_count = in_chunk.attributes.get('objects_count')
    assert isinstance(objects_count, dict)
    assert objects_count.get('8') == 1
    assert objects_count.get('0') == 1
    assert objects_count.get('7') == 1

    # e_v_i should contain 3-element lists for osds 0,7,8
    e_v_i = in_chunk.attributes.get('e_v_i')
    assert isinstance(e_v_i, dict)
    assert e_v_i.get('0') == [28, 2, 25]
    assert e_v_i.get('7') == [28, 2, 25]
    assert e_v_i.get('8') == [28, 2, 25]

    # Ensure WaitReplicas child does NOT have these attributes
    wr = _find_span_by_state(b.completed_spans, "PrimaryActive/Session/ActiveScrubbing/in-chunk/WaitReplicas")
    assert wr is not None
    assert 'objects_count' not in wr.attributes
    assert 'e_v_i' not in wr.attributes


def test_objects_extraction_unsecure():
    parser = LogParser()
    # unsecure -> original object names are stored
    b = TraceBuilder(debug=False, fixed=True, objects=True, unsecure_objects=True)

    lines = [
        "2026-02-14T17:10:03.117+0000 ... osd.3 pg[2.3(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: select_auth_object: 2:ff7b1f36:::obj1:12 shard 3 got:{...}",
        "2026-02-14T17:10:03.117+0000 ... osd.3 pg[2.3(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: select_auth_object: selecting osd 3 for obj 2:ff7b1f36:::obj1:12 with oi ...",
        "2026-02-14T17:10:04.000+0000 ... osd.3 pg[2.3(...)] scrubber<NotActive>: FSM: -- state -->> NotActive",
    ]

    for l in lines:
        parsed = parser.parse_line(l)
        if parsed:
            b.process_entry(parsed)
    b.finalize()

    in_chunk = None
    for s in b.completed_spans:
        if s.state_name == 'PrimaryActive/Session/ActiveScrubbing/in-chunk':
            in_chunk = s
            break
    assert in_chunk is not None
    objs = in_chunk.attributes.get('objects')
    assert isinstance(objs, set)
    assert '2:ff7b1f36:::obj1:12' in objs


def test_objects_extraction_hashed_with_salt():
    import hashlib
    parser = LogParser()
    salt = 'somesalt'
    b = TraceBuilder(debug=False, fixed=True, objects=True, objects_hash_salt=salt)

    obj = '2:ff7b1f36:::obj1:12'
    lines = [
        f"2026-02-14T17:10:03.117+0000 ... osd.3 pg[2.3(...)] scrubber<Session/Act/WaitReplicas>:  b.e.: select_auth_object: {obj} shard 3 got:{{...}}",
        "2026-02-14T17:10:04.000+0000 ... osd.3 pg[2.3(...)] scrubber<NotActive>: FSM: -- state -->> NotActive",
    ]

    for l in lines:
        parsed = parser.parse_line(l)
        if parsed:
            b.process_entry(parsed)
    b.finalize()

    in_chunk = None
    for s in b.completed_spans:
        if s.state_name == 'PrimaryActive/Session/ActiveScrubbing/in-chunk':
            in_chunk = s
            break
    assert in_chunk is not None
    objs = in_chunk.attributes.get('objects')
    assert isinstance(objs, set)
    expected = hashlib.sha256((salt + obj).encode('utf-8')).hexdigest()
    assert expected in objs


def test_session_success_false_on_mid_scrub_abort_and_reserving_not_completed():
    parser = LogParser()

    # Case A: abort via on_mid_scrub_abort -> failure with reason
    b1 = TraceBuilder(debug=False, fixed=True)
    lines_abort = [
        "2026-02-11T08:22:55.304+0000 ... osd.3 pg[2.3(...)] scrubber<Session/Act/WaitReplicas>: FSM: WaitReplicas::react(...)",
        "2026-02-11T08:23:00.471+0000 ... osd.3 pg[2.3(...)] scrubber<Session/Act/WaitReplicas>: on_mid_scrub_abort: executing target: ... Abort cause: interval",
        # closing the session via reset
        "2026-02-11T08:23:01.000+0000 ... osd.3 pg[2.3(...)] scrubber<NotActive>: FSM: -- state -->> NotActive",
    ]
    for l in lines_abort:
        parsed = parser.parse_line(l)
        if parsed:
            b1.process_entry(parsed)
    b1.finalize()

    sess1 = None
    for s in b1.completed_spans:
        if s.state_name == 'PrimaryActive/Session':
            sess1 = s
            break
    assert sess1 is not None
    assert sess1.attributes.get('successful') == 'false'
    assert sess1.attributes.get('failure_reason') == 'interval'

    # Case B: never reached ActiveScrubbing -> failure with reserving-replicas reason
    b2 = TraceBuilder(debug=False, fixed=True)
    lines_no_active = [
        "2026-02-11T08:30:00.000+0000 ... osd.4 pg[3.1(...)] scrubber<Session>: FSM: -- state -->> Session",
        # directly go to PrimaryIdle (reset) without reaching ActiveScrubbing
        "2026-02-11T08:30:05.000+0000 ... osd.4 pg[3.1(...)] scrubber<PrimaryActive/PrimaryIdle>: FSM: -- state -->> PrimaryActive/PrimaryIdle",
    ]
    for l in lines_no_active:
        parsed = parser.parse_line(l)
        if parsed:
            b2.process_entry(parsed)
    b2.finalize()

    sess2 = None
    for s in b2.completed_spans:
        if s.state_name == 'PrimaryActive/Session':
            sess2 = s
            break
    assert sess2 is not None
    assert sess2.attributes.get('successful') == 'false'
    assert sess2.attributes.get('failure_reason') == 'reserving replicas not completed'

    # Case C: successful session (reached ActiveScrubbing and no abort)
    b3 = TraceBuilder(debug=False, fixed=True)
    lines_ok = [
        "2026-02-11T08:40:00.000+0000 ... osd.5 pg[4.1(...)] scrubber<Session/Act/WaitReplicas>: FSM: WaitReplicas::react(...)",
        # transition away to close session
        "2026-02-11T08:40:10.000+0000 ... osd.5 pg[4.1(...)] scrubber<NotActive>: FSM: -- state -->> NotActive",
    ]
    for l in lines_ok:
        parsed = parser.parse_line(l)
        if parsed:
            b3.process_entry(parsed)
    b3.finalize()

    sess3 = None
    for s in b3.completed_spans:
        if s.state_name == 'PrimaryActive/Session':
            sess3 = s
            break
    assert sess3 is not None
    assert sess3.attributes.get('successful') == 'true'
    assert 'failure_reason' not in sess3.attributes
