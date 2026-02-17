# Developer Setup Guide

Everything you need to get PuppetString running for development.

## Prerequisites

- **Python 3.13** (64-bit Windows installer from [python.org](https://www.python.org/downloads/))
- **Git** (already installed if you're reading this from the repo)
- **GitHub CLI** (`gh`) — installed and authenticated (`gh auth login`)

## Understanding the Environment

### What is a "virtual environment" (venv)?

A venv is a **folder** that holds a private copy of Python and any packages
you install for this project. It keeps PuppetString's dependencies separate
from other Python projects on your machine. It's not a virtual machine — just
an isolated folder.

### Why is the venv on C: instead of Y:?

Python's venv tool creates symlinks (shortcuts), and Windows doesn't allow
symlinks on network shares (Y: drive). So the venv lives on the local C: drive
while the actual code lives on Y:. This is totally fine — you just need to
activate the venv before working.

### What is PATH?

PATH is a list of folders that Windows searches when you type a command. When
you type `python`, Windows goes through every folder in PATH looking for
`python.exe`. If the folder isn't in PATH, Windows says "command not found"
even though the program is installed.

To edit PATH: Start Menu → search "Environment Variables" → Edit the system
environment variables → Environment Variables → User variables → Path → Edit.

## Setup Steps

### 1. Install Python 3.13 (64-bit)

Download the **Windows installer (64-bit)** from [python.org](https://www.python.org/downloads/).
Make sure to check **"Add python.exe to PATH"** during installation.

If you forgot to check it, add these two entries to your PATH manually:
```
C:\Users\<username>\AppData\Local\Programs\Python\Python313\
C:\Users\<username>\AppData\Local\Programs\Python\Python313\Scripts\
```

### 2. Create the Virtual Environment

Open a terminal (PowerShell or Command Prompt) and run:

```powershell
# Create the venv on the local C: drive (avoids network share issues)
py -3.13 -m venv C:\Users\<username>\.venvs\puppetstring --copies
```

### 3. Activate the Venv

**You need to do this every time you open a new terminal to work on PuppetString.**

```powershell
# PowerShell
C:\Users\<username>\.venvs\puppetstring\Scripts\Activate.ps1

# Command Prompt
C:\Users\<username>\.venvs\puppetstring\Scripts\activate.bat

# Git Bash / MSYS2
source /c/Users/<username>/.venvs/puppetstring/Scripts/activate
```

When activated, your prompt will show `(puppetstring)` at the beginning.

### 4. Install PuppetString

```powershell
cd <project-root>
pip install -e ".[dev]"
```

The `-e` flag means "editable" — when you change the code, the changes take
effect immediately without reinstalling. The `[dev]` part installs extra
tools for development (pytest, ruff, mypy).

### 5. Verify Everything Works

```powershell
# Check the CLI works
puppetstring --help

# Run the tests
pytest tests/ -v

# Run the linter
ruff check puppetstring/ tests/
```

## Daily Workflow

1. Open terminal
2. Activate venv: `C:\Users\<username>\.venvs\puppetstring\Scripts\Activate.ps1`
3. Navigate to project: `cd <project-root>`
4. Do your work
5. Run tests before committing: `pytest tests/ -v`
6. Run linter: `ruff check puppetstring/ tests/`

## Troubleshooting

### "python: command not found"
Python isn't on PATH. See step 1 above.

### "puppetstring: command not found"
The venv isn't activated. See step 3 above.

### "pip install fails with Rust/Cargo errors"
You probably have 32-bit Python or a very new Python version (3.14+). Make
sure you have the **64-bit** Python 3.13 installer from python.org.

### "Access denied" when creating venv on Y: drive
The venv can't live on the network share. Create it on C: instead (step 2).

### Tests show a "PytestCacheWarning" about Y: drive
Harmless. pytest can't write its cache to the network share. Tests still pass.

## Project Structure (Quick Reference)

```
<project-root>\          ← Code lives here (network share)
C:\Users\<username>\.venvs\puppetstring\  ← Venv lives here (local drive)

puppetstring/                ← The actual Python package
  cli.py                     ← CLI commands (pull, tangle, cut, dance, unravel, stage)
  config.py                  ← Configuration loading (.puppetstring.toml)
  core/                      ← Core engine (orchestration, results, LLM client)
  adapters/                  ← Target-specific adapters (MCP, HTTP, LangChain)
  modules/                   ← Attack modules (the heart of the tool)
    mcp_scanner/             ← MCP server scanning
    workflow_fuzzer/          ← Agent workflow fuzzing
    prompt_injection/         ← Indirect prompt injection
    agent_swarm/             ← Agent-to-agent attacks
    owasp_audit/             ← Full OWASP coverage audit
  payloads/                  ← Shared attack payload library (YAML files)
  reporting/                 ← Report generation (HTML, JSON, Markdown)
  staging/                   ← Test target deployment
  utils/                     ← Logging, constants, helpers
tests/                       ← Test suite
docs/                        ← Documentation
examples/                    ← Vulnerable test targets for practicing
```
