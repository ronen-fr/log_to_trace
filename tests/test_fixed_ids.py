import pytest

from log_to_trace import TraceBuilder


def test_fixed_ids_increment_sequentially():
    # Create builder with fixed IDs enabled
    b = TraceBuilder(debug=False, fixed=True)

    # Create a top-level span (trace id should be "1", first span id "1")
    s1 = b.create_span("1.1", "osd.1", "PrimaryActive/Session", act_set=[1], parent_span_id=None, line_ts=None)

    # Create a child span (should get span id "2")
    s2 = b.create_span("1.1", "osd.1", "PrimaryActive/Session/ActiveScrubbing", act_set=[1], parent_span_id=s1.span_id, line_ts=None)

    # Close spans so they appear in completed_spans
    b.close_span(s2)
    b.close_span(s1)

    # Verify sequential IDs
    assert s1.span_id == "1"
    assert s2.span_id == "2"

    # Trace IDs: first trace should be "1"
    assert s1.trace_id == "1"
    assert s2.trace_id == "1"

    # Creating a new trace id for a different PG should increment trace counter
    t2 = b.new_trace_id("2.2")
    assert t2 == "2"


def test_fixed_ids_consistent_across_create_and_new_trace():
    b = TraceBuilder(debug=False, fixed=True)
    s1 = b.create_span("p1", "osd.1", "PrimaryActive/Session", act_set=[1], parent_span_id=None)
    # after creating first span, next trace id (when requested) increments
    t = b.new_trace_id("p2")
    assert t == "2"
    s2 = b.create_span("p2", "osd.2", "PrimaryActive/Session", act_set=[2], parent_span_id=None)
    assert s2.trace_id == "2"


if __name__ == '__main__':
    pytest.main([__file__])
