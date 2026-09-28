"""
The test suite: one module per area of the code, see README.md.

Output is made colourless here, before any test module imports probolos.
report.py decides once, at import, whether stdout is a terminal; run from one,
the rendered report carried escape codes in the middle of the phrases the tests
look for, so the suite passed in CI and failed at a developer's prompt.
NO_COLOR also turns off the colour Python 3.14's argparse and unittest add.
"""

import os

os.environ["NO_COLOR"] = "1"
