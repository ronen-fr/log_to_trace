import tempfile
from pathlib import Path

from log_to_trace import LogParser, TraceBuilder, parse_iso_to_ns, process_sorted_logs


def _write_tmp_log(tmpdir, lines):
    p = Path(tmpdir) / "sample.log"
    p.write_text('\n'.join(lines) + '\n')
    return str(p)


def test_process_sorted_logs_filters_by_pg_and_time(tmp_path):
    lines = [
        "2026-01-01T00:00:00+0000 0 0 osd.1 pg[1.1( )] scrubber<Session>: FSM: -- state -->> Session",
        "2026-02-01T00:00:00+0000 0 0 osd.2 pg[2.2( )] scrubber<Session>: FSM: -- state -->> Session",
    ]
    fn = _write_tmp_log(tmp_path, lines)

    parser = LogParser()
    builder = TraceBuilder(debug=False, fixed=True)

    # Filter to only pg 1.1 and time <= 2026-01-31
    pg_filter = { '1.1' }
    start_ns = None
    end_ns = parse_iso_to_ns('2026-01-31T23:59:59+0000')

    process_sorted_logs([fn], parser, builder, pg_ids=pg_filter, start_ns=start_ns, end_ns=end_ns)
    builder.finalize()

    # Ensure we only processed PG 1.1
    pgs = { s.attributes.get('pg.id') for s in builder.completed_spans }
    assert '1.1' in pgs
    assert '2.2' not in pgs
