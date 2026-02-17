"""Allow running PuppetString as a module: python -m puppetstring.

This file is what makes `python -m puppetstring` work. Python looks for
__main__.py inside a package when you use the -m flag. It just calls the
same CLI app that `puppetstring` (the installed command) would call.
"""

from puppetstring.cli import app

app()
