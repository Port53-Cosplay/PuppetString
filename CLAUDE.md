# PuppetString — Claude Code Project Instructions

## Project Overview

PuppetString is an open-source Python red team toolkit for testing the security of AI agents, agentic workflows, and MCP servers. It maps to the OWASP Top 10 for Agentic AI Applications (2026).

- **Full project plan:** `PUPPETSTRING_PROJECT_PLAN.md` (read this for architecture, module specs, and current status)
- **GitHub:** https://github.com/Port53-Cosplay/PuppetString
- **Local path:** <project-root>

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
