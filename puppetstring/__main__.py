"""Allow running PuppetString as a module: python -m puppetstring.

This file is what makes `python -m puppetstring` work. Python looks for
__main__.py inside a package when you use the -m flag. It just calls the
same CLI app that `puppetstring` (the installed command) would call.
"""

import io
import sys

# Rich uses Unicode box-drawing characters and symbols that the default
# Windows console encoding (cp1252) cannot handle. Force UTF-8 stdout
# before any Rich import or output happens.
if sys.platform == "win32" and not isinstance(sys.stdout, io.StringIO):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]

from puppetstring.cli import app  # noqa: E402

app()
