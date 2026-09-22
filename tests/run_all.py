"""Run unittest classes AND the standalone descriptor tests: python -m tests.run_all.

Restricted containers may prohibit creating listening AF_UNIX sockets. Only
tests requiring that exact capability are skipped; socketpair IPC still runs.
"""
import importlib
import inspect
from pathlib import Path
import socket
import unittest


def main():
    unavailable = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.close()
    except PermissionError as exc:
        unavailable = str(exc)
    suite = unittest.TestSuite()
    # rglob, not glob: tests/audit/ holds one module per security review and a
    # top-level glob collected none of them, so `python -m tests.run_all` and
    # `unittest discover` reported different totals -- which README.md says is
    # itself a bug, and was one before for the same kind of reason.
    root = Path(__file__).parent
    for path in sorted(root.rglob("test_*.py")):
        dotted = ".".join(path.relative_to(root).with_suffix("").parts)
        module = importlib.import_module(f"tests.{dotted}")
        if unavailable:
            for name in ("TestAgentLink", "AgentSocketHardening",
                         "SocketOwnership", "SocketMetadataIsNotChangedByName"):
                cls = getattr(module, name, None)
                if cls is not None:
                    for method in unittest.defaultTestLoader.getTestCaseNames(cls):
                        if method == "test_peer_credentials_report_this_process":
                            continue  # this one uses socketpair, which is available
                        setattr(cls, method, unittest.skip(
                            f"AF_UNIX socket creation prohibited: {unavailable}"
                        )(getattr(cls, method)))
        suite.addTests(unittest.defaultTestLoader.loadTestsFromModule(module))
        for name, fn in inspect.getmembers(module, inspect.isfunction):
            if name.startswith("test_") and fn.__module__ == module.__name__:
                suite.addTest(unittest.FunctionTestCase(fn))
    result = unittest.TextTestRunner(verbosity=2, buffer=True).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
