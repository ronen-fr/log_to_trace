# log_to_trace
A python script to process OSD logs, extract scrubber states (for each scrub session performed), and create Jaeger-formatted spans in a json output file

Using the script:

python3 log_to_trace.py ceph-osd*log --out all_scrub_states.json

Options:
- `--debug` / `-d` : Enable debug logging
- `--fixed` : Use deterministic sequential IDs (trace and span IDs will be "1", "2", ...) — useful for reproducible debugging and testing

Notes:
- The input files can be gzipped.
- The `--out` filename is optional.
- Intermediate files are created and not removed (intentionally).

Here is how the traces created might look in a Jaeger viewer: ![as seen in Jaeger Viewer](https://github.com/ronen-fr/log_to_trace/blob/main/spans_exmp_1.png "as seen in Jaeger Viewer")
