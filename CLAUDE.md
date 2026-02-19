# PuppetString — Claude Code Project Instructions

## Project Overview

PuppetString is an open-source Python red team toolkit for testing the security of AI agents, agentic workflows, and MCP servers. It maps to the OWASP Top 10 for Agentic AI Applications (2026).

- **Full project plan:** `PUPPETSTRING_PROJECT_PLAN.md` (read this for architecture, module specs, and current status)
- **GitHub:** https://github.com/Port53-Cosplay/PuppetString

## Development Environment (READ THIS AFTER COMPACTION)

These details get lost when conversation context is compacted. Re-read this section.

- **Python venv:** On local drive (not in repo) because network shares block symlinks. See `docs/DEV_SETUP.md` for exact paths.
- **Activate venv before running anything.** If pytest or another tool isn't found, the venv probably isn't activated — tell the user, don't try to fix it.
- **The user runs commands themselves** in their own terminal. Do NOT try to `pip install` packages without asking first.
- **Running tests:** `python -m pytest tests/ -x -q` (from the project root, with venv activated).
- **Linting:** `ruff check puppetstring/ tests/` (ruff is installed in the venv).
- **Formatting:** `ruff format puppetstring/ tests/` — CI also runs `ruff format --check`, so always run the formatter before committing or CI will fail.
- **The user runs the vulnerable test agent** (`examples/vulnerable_agent/llm_agent.py`) manually in a separate terminal against a local Ollama instance. The default model is `llama3.1:8b`. Don't try to start/stop Ollama or the agent — the user handles that.
- **The user runs fuzzing commands** (`puppetstring pull -t http://127.0.0.1:8000 --type tool-abuse`) in their own terminal and pastes results or points to an error file. Read the file when asked, don't try to run the commands yourself.
- **Shell quirks:** The user's terminal is PowerShell on Windows. Curly braces in commands (like curl with JSON) cause issues — use Python scripts instead.

## CLI Command Names (MANDATORY — Read This First)

PuppetString uses themed command names based on a puppet metaphor. **These are the ONLY command names allowed.** Do NOT use generic alternatives under any circumstances.

| Command | What It Does | Metaphor |
|---|---|---|
| `puppetstring pull` | MCP scanning + workflow fuzzing | Pulling the strings |
| `puppetstring tangle` | Indirect prompt injection testing | Tangling up the agent's inputs |
| `puppetstring cut` | Agent-to-agent attacks | Cutting the strings of trust |
| `puppetstring dance` | Full OWASP audit | Making the whole system dance |
| `puppetstring unravel` | Report generation (HTML/JSON/Markdown) | Unraveling what went wrong |
| `puppetstring stage` | Deploy/teardown vulnerable test targets | Setting the stage |

### NEVER use these generic names — they are WRONG:

- ~~`scan`~~ → use `pull --type scan`
- ~~`fuzz`~~ → use `pull --type [tool-abuse|memory-poison|boundary|chain|all]`
- ~~`inject`~~ → use `tangle`
- ~~`swarm`~~ → use `cut`
- ~~`audit`~~ → use `dance`
- ~~`report`~~ → use `unravel`
- ~~`setup`~~ / ~~`deploy`~~ / ~~`init`~~ → use `stage`

### Module directories stay descriptive (these are internal, not user-facing):

- `puppetstring/modules/mcp_scanner/` — used by `pull --type scan`
- `puppetstring/modules/workflow_fuzzer/` — used by `pull --type [fuzz types]`
- `puppetstring/modules/prompt_injection/` — used by `tangle`
- `puppetstring/modules/agent_swarm/` — used by `cut`
- `puppetstring/modules/owasp_audit/` — used by `dance`
- `puppetstring/reporting/` — used by `unravel`
- `puppetstring/staging/` — used by `stage`

## Glossary — Key Concepts in Plain English

If you're new to this space, here's what the jargon means. This section exists
so that anyone picking up this project can understand what we're building and why.

### What is an "AI Agent"?

A regular chatbot just talks — you ask it something, it answers. An **AI agent**
can *do things*. It has tools: it can read files, search the web, send emails,
query databases, run code. Think of it as an AI with hands, not just a mouth.
That's powerful, but it's also dangerous — because now an attacker doesn't just
trick an AI into *saying* something bad, they can trick it into *doing* something bad.

### What is MCP (Model Context Protocol)?

**MCP** is like a USB port for AI agents. It's a standard protocol (created by
Anthropic) that defines how AI agents discover and use tools.

- An **MCP server** exposes tools (e.g., "read a file", "query a database",
  "run a shell command"). It's a program that sits there waiting for an AI to
  connect and ask what tools are available.
- An **MCP client** (the AI agent) connects to the server, sees the menu of
  available tools, and uses them.

**Why it's a security problem:** Most MCP servers were built for convenience,
not security. They often require no authentication (anyone can connect), expose
dangerous tools (shell execution, unrestricted file reads), do no input validation
(you can pass `../../etc/passwd` to a file-read tool), and have no rate limiting.
PuppetString's scanner connects to MCP servers and flags all of this.

### What is OWASP?

**OWASP** (Open Worldwide Application Security Project) is a nonprofit that
publishes free security guidance. Their "Top 10" lists are industry-standard
references for the most critical risks in a given domain. The **OWASP Top 10
for Agentic AI (2026)** is specifically about risks in AI systems that can take
actions — which is exactly what PuppetString tests for.

### What is a "Red Team"?

In security, a **red team** is the group that pretends to be the attacker. They
try to break into systems, find vulnerabilities, and exploit weaknesses — but
they do it with permission, so the organization can fix the problems before real
attackers find them. PuppetString is a red team tool for AI agents.

### What is Prompt Injection?

**Prompt injection** is tricking an AI by hiding instructions in its input.
- **Direct:** You tell the AI "ignore your instructions and do X instead."
- **Indirect:** You hide instructions in a document, email, or web page that
  the AI reads as part of its job. The AI follows the hidden instructions
  without realizing they're from an attacker, not from the user.

Indirect prompt injection is the #1 practical attack against deployed agents,
and it's what PuppetString's `tangle` command tests for.

### What is "Fuzzing"?

**Fuzzing** means throwing a lot of weird, unexpected, or malicious inputs at
something to see what breaks. PuppetString's `pull` command fuzzes AI agents —
it sends crafted messages designed to trick the agent into misusing its tools,
leaking its instructions, or breaking out of its intended boundaries.

## Security-First Development (NON-NEGOTIABLE)

This is a security tool. The code we ship must be exemplary. Every line written should reflect that.

### Code Security Rules

1. **Never hardcode secrets, API keys, or credentials.** Always use environment variables or config files that are gitignored.
2. **Validate and sanitize ALL external input.** This includes CLI arguments, config file values, API responses, YAML payload files, and target responses. Trust nothing.
3. **No shell injection vectors.** Never pass unsanitized strings to `subprocess`, `os.system`, or shell commands. Use `subprocess.run()` with `shell=False` and argument lists.
4. **No eval/exec.** Never use `eval()`, `exec()`, or `compile()` on untrusted data. No pickle deserialization of untrusted data.
5. **No path traversal vulnerabilities.** When handling file paths, always resolve and validate against an expected base directory. Use `pathlib` and check with `.resolve()`.
6. **Parameterize database queries.** Never construct SQL strings with f-strings or concatenation.
7. **Pin dependencies.** Use exact versions in pyproject.toml to prevent supply chain attacks.
8. **Handle errors explicitly.** No bare `except:` blocks. Catch specific exceptions. Never silently swallow errors.
9. **Secrets in logs.** Never log API keys, tokens, passwords, or full target responses that might contain sensitive data. Sanitize before logging.
10. **YAML safety.** Always use `yaml.safe_load()`, never `yaml.load()` without a safe Loader.

### Before Completing Any Task

Ask yourself: "If someone audited this code at a security conference, would it hold up?" If not, fix it first.

## Coding Standards

- **Python 3.11+** — use modern features (match/case, type hints, dataclasses)
- **Type hints on all function signatures** — no exceptions
- **Pydantic models** for data structures that cross boundaries (config, results, API responses)
- **async/await** for all I/O operations (HTTP, MCP connections, file operations where appropriate)
- **Docstrings** on public classes and functions (one-liner is fine if the name is clear)
- **No print() statements** — use Rich console or the structured logger
- **Formatting/linting:** ruff (will be configured in pyproject.toml)

## Project Conventions

- **CLI framework:** Typer
- **HTTP client:** httpx (async)
- **LLM calls:** LiteLLM
- **Terminal output:** Rich
- **Testing:** pytest + pytest-asyncio
- **Config format:** TOML (`.puppetstring.toml`)
- **Payload format:** YAML files
- **Report templates:** Jinja2
- **Package name:** `puppetstring` (lowercase, one word)
- **CLI command:** `puppetstring`

## Git Workflow

- **Branch:** `main` (single branch is fine for now)
- **Commits:** Descriptive messages, commit at meaningful milestones
- **Pushes:** Infrequent — batch up work and push when ready. Don't push automatically.
- **Never commit:** `.env` files, API keys, `puppetstring_results/` output, `__pycache__`

## Testing Requirements

- Write tests alongside new code, not as an afterthought
- Mock external dependencies (LLM APIs, MCP servers, HTTP targets) in unit tests
- Use fixtures for reusable test data
- Tests must pass before considering a task complete
