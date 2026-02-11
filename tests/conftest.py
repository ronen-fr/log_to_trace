import os
import sys

# Ensure the project root (one level up from tests/) is on sys.path so tests
# can import the top-level module `log_to_trace.py` as `log_to_trace`.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
