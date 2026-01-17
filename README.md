# log_to_trace
A python script to process OSD logs, extract scrubber states (for each scrub session performed), and create Jaeger-formatted spans in a json output file

Using the script:
python3 log_to_trace.py ceph-osd*log --out all_scrub_states.json

Note: the input files can be gzipped.
Note: the 'out' filename is optional.
Note: intermediate files are created and not removed (intentionally).
