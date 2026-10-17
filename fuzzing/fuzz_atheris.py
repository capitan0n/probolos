#!/usr/bin/env python3
"""
libFuzzer-driven fuzzing through atheris -- optional, same targets as
heavy_fuzz.py (targets.py).

    pip install atheris            # wheels exist for CPython 3.13 and 3.14
    python fuzzing/fuzz_atheris.py descriptors -max_total_time=600 \\
        fuzzing/corpus/queue/descriptors
    python fuzzing/fuzz_atheris.py protocol_request -max_len=8256 -jobs=4

The first argument is the target (see `heavy_fuzz.py --list`); everything
after it goes to libFuzzer (-runs, -max_total_time, -jobs, -dict, corpus
dirs...). Pointing it at heavy_fuzz's corpus/<group> or corpus/queue/<group>
reuses what that already found, and heavy_fuzz loads what atheris adds there.
With -jobs/-workers libFuzzer re-runs this file without the target name; it
is passed on in PROBOLOS_FUZZ_TARGET.

Why both? atheris instruments bytecode and gets libFuzzer's comparison
feedback (it solves magic values like b"EFI PART" by itself); heavy_fuzz
needs nothing to install and runs everywhere.
"""
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent), str(HERE)]

import atheris  # noqa: E402

if len(sys.argv) >= 2 and not sys.argv[1].startswith("-"):
    NAME = sys.argv.pop(1)
    os.environ["PROBOLOS_FUZZ_TARGET"] = NAME     # for -jobs children
else:
    NAME = os.environ.get("PROBOLOS_FUZZ_TARGET") or sys.exit(__doc__)

with atheris.instrument_imports(include=["probolos"]):
    import targets  # noqa: E402

if NAME not in targets.TARGETS:
    sys.exit(f"unknown target {NAME!r}; one of: {', '.join(targets.TARGETS)}")
FN = targets.TARGETS[NAME]


def TestOneInput(data: bytes) -> None:
    FN(data)       # expected errors are handled inside; anything else crashes


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
