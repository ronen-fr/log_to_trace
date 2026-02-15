import sys

from log_to_trace import parse_arguments


def test_out_appends_json_when_missing_equals():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--out=outfile', 'input.log']
        args = parse_arguments()
        assert args.output_file == 'outfile.json'
    finally:
        sys.argv = old


def test_out_appends_json_when_missing_separate():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--out', 'outfile', 'input.log']
        args = parse_arguments()
        assert args.output_file == 'outfile.json'
    finally:
        sys.argv = old


def test_out_keeps_json_suffix():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--out=result.json', 'input.log']
        args = parse_arguments()
        assert args.output_file == 'result.json'
    finally:
        sys.argv = old


def test_parse_pg_and_time_args():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--pg=2.2,3.3', '--start=2026-01-01', '--end=2026-01-02', 'input.log']
        args = parse_arguments()
        assert args.pg_ids == { '2.2', '3.3' }
        assert isinstance(args.start_ns, int) and isinstance(args.end_ns, int)
        assert args.start_ns < args.end_ns
    finally:
        sys.argv = old


def test_parse_start_invalid_exits():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--start=not-a-date', 'input.log']
        try:
            parse_arguments()
            assert False, 'parse_arguments should have exited on invalid --start'
        except SystemExit:
            pass
    finally:
        sys.argv = old


def test_objects_unsecure_and_salt_conflict():
    old = sys.argv
    try:
        sys.argv = ['log_to_trace.py', '--objects', '--unsecure-objects', '--objects-hash-salt=abc', 'input.log']
        try:
            parse_arguments()
            assert False, 'parse_arguments should have exited due to conflicting options'
        except SystemExit:
            pass
    finally:
        sys.argv = old
