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
