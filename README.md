# PuppetString

[![CI](https://github.com/Port53-Cosplay/PuppetString/actions/workflows/ci.yml/badge.svg)](https://github.com/Port53-Cosplay/PuppetString/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> *"Because your AI agent shouldn't be your biggest insider threat."*

**PuppetString** is an open-source red team toolkit for testing the security of AI agents, agentic workflows, and MCP servers. It helps security teams answer the question: **"What happens when someone tries to trick, abuse, or weaponize our AI agents?"**

## Why This Exists

The agentic AI attack surface is brand new. MCP security was described at Black Hat 2025 as *"like Swiss cheese"*. Enterprise AI agents are being deployed faster than anyone can secure them. PuppetString fills that gap with repeatable, automated offensive tests that map to the [OWASP Top 10 for Agentic AI Applications (2026)](https://owasp.org/www-project-top-10-for-large-language-model-applications/).

## What It Tests

| Command | What It Does | Metaphor |
|---|---|---|
| `puppetstring pull` | MCP scanning + workflow fuzzing | *Pulling the strings* |
| `puppetstring tangle` | Indirect prompt injection testing | *Tangling up the inputs* |
| `puppetstring cut` | Agent-to-agent attack simulation | *Cutting the strings of trust* |
| `puppetstring dance` | Full OWASP agentic AI audit | *Making the whole system dance* |
| `puppetstring unravel` | Generate HTML/JSON/Markdown reports | *Unraveling what went wrong* |
| `puppetstring stage` | Deploy/teardown vulnerable test targets | *Setting the stage* |

## OWASP Agentic AI Coverage

| # | Risk | PuppetString Coverage |
|---|---|---|
| A1 | Excessive Agency | `pull` (tool enumeration, permission mapping) |
| A2 | Uncontrolled Tool Execution | `pull` (tool abuse sequences) |
| A3 | Prompt Injection via Tools | `tangle` (data source injection) |
| A4 | Insecure Output Handling | `pull` (output chain testing) |
| A5 | Memory & Context Manipulation | `pull` (memory poisoning) |
| A7 | Multi-Agent Trust Exploitation | `cut` (cross-agent attacks) |
| A8 | Identity & Access Mismanagement | `pull` (auth/permission audit) |
| A9 | Inadequate Logging & Monitoring | `unravel` (flags logging gaps) |
| A10 | Supply Chain Vulnerabilities | `pull` (supply chain checks) |

## Quick Start

### Requirements

- Python 3.11+ (3.13 recommended)
- pip

### Install

```bash
pip install puppetstring
```

Or install from source for development:

```bash
git clone https://github.com/Port53-Cosplay/PuppetString.git
cd PuppetString
pip install -e ".[dev]"
```

### First Run

```bash
# See all commands
puppetstring --help

# Read the responsible use policy first
puppetstring --responsible-use

# Deploy the included vulnerable test targets
puppetstring stage up

# Scan a vulnerable MCP server
puppetstring pull -t mcp://localhost:3000

# Fuzz a vulnerable agent
puppetstring pull -t http://localhost:8000 --type all

# Generate a report
puppetstring unravel -r ./puppetstring_results -f html
```

## Project Status

**Current Phase:** Phase 0 — Scaffolding complete, CLI working, tests passing.

See [PUPPETSTRING_PROJECT_PLAN.md](PUPPETSTRING_PROJECT_PLAN.md) for the full roadmap.

## Responsible Use

PuppetString is a security testing tool. **Only use it against systems you own or have explicit authorization to test.** See [RESPONSIBLE_USE.md](RESPONSIBLE_USE.md) for the full policy.

## License

MIT — see [LICENSE](LICENSE).
