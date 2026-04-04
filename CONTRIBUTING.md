# Contributing to pyvulscan

Thank you for your interest in contributing! This document covers everything you need to know to get started, submit changes, and understand how this project is maintained.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Running Tests](#running-tests)
- [Code Style](#code-style)
- [Submitting Changes](#submitting-changes)
- [Commit Message Convention](#commit-message-convention)
- [Reporting Bugs](#reporting-bugs)
- [Requesting Features](#requesting-features)
- [Security Vulnerabilities](#security-vulnerabilities)
- [Release Process](#release-process)

---

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/). By participating, you agree to uphold a respectful and inclusive environment. Report unacceptable behavior to rodrigo.pp.toledo@gmail.com.

---

## Getting Started

### Prerequisites

- Python 3.11 or higher
- [uv](https://docs.astral.sh/uv/) (recommended) or pip

### Fork and clone

```bash
# Fork the repo on GitHub, then:
git clone https://github.com/<your-username>/pyau.git
cd pyau
```

### Install dependencies

```bash
uv sync --dev
```

This installs the package in editable mode along with all development dependencies (pytest, ruff, mypy, bump-my-version).

### Verify the setup

```bash
uv run pytest -v
uv run ruff check src/
uv run mypy src/
```

All checks should pass on a clean checkout.

---

## Project Structure

```
src/pyau/
├── cli.py              # Entry point — argparse CLI, scan + multiscan dispatch
├── report.py           # Output formatting (plain text, JSON, filter section)
├── severity.py         # CVSS severity extraction and threshold comparison
├── multiscan.py        # Multiscan config loading and parallel scan orchestration
├── osv/
│   ├── client.py       # OSV API HTTP client (batch query + vuln details)
│   └── processor.py    # Result processing — parallel fetch of vuln details
├── parsers/
│   ├── detect.py       # Auto-detection and routing by file type
│   ├── poetry.py       # poetry.lock and pyproject.toml parser
│   ├── uv.py           # uv.lock parser
│   ├── requirements.py # requirements.txt parser
│   └── utils.py        # Shared utilities (TOML loading, name normalization)
└── mcp/
    └── server.py       # FastMCP server exposing 3 tools for LLM integration
```

---

## Development Workflow

1. **Create a branch** from `main` using a descriptive name:

```bash
git checkout -b feat/my-feature
# or
git checkout -b fix/issue-description
```

Branch naming convention:

| Prefix | Use for |
|---|---|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation only |
| `refactor/` | Code changes with no behaviour change |
| `test/` | Adding or fixing tests |
| `chore/` | Tooling, CI, dependencies |

2. **Make your changes** — keep commits focused and atomic.

3. **Run the full check suite** before opening a PR:

```bash
uv run pytest -v
uv run ruff check src/
uv run mypy src/
```

4. **Open a Pull Request** against `main`.

---

## Running Tests

```bash
# All tests
uv run pytest -v

# Specific file
uv run pytest tests/unit/test_parser.py -v

# With coverage (requires pytest-cov)
uv run pytest --cov=pyau --cov-report=term-missing
```

Tests live under `tests/`. Unit tests go in `tests/unit/`. If you add new functionality, add corresponding tests.

---

## Code Style

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting, and [mypy](https://mypy-lang.org/) for type checking.

```bash
# Check linting
uv run ruff check src/

# Auto-fix
uv run ruff check src/ --fix

# Type check
uv run mypy src/
```

Key conventions:

- Line length: **100 characters**
- Target: **Python 3.11+** — use modern syntax (`X | Y` unions, `match`, etc.)
- Type annotations on all public functions
- No docstrings on functions whose purpose is self-evident from the name and types
- No speculative abstractions — solve the problem at hand, not hypothetical future ones

---

## Submitting Changes

1. Ensure all tests and linting pass locally
2. Open a Pull Request against `main`
3. Fill in the PR description — what changed, why, and how to test it
4. A maintainer will review and either approve, request changes, or close with explanation
5. Once approved and merged, a new release may be cut at the maintainer's discretion

**Please do not bump the version yourself** — version management is handled by the maintainer as part of the release process.

---

## Commit Message Convention

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]

[optional footer]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`, `perf`

Examples:

```
feat(multiscan): add YAML config support
fix(parser): handle uv.lock editable packages correctly
docs: add CONTRIBUTING guide
chore(ci): fix publish workflow tag check
```

---

## Reporting Bugs

Open an issue at [github.com/statspyml/pyau/issues](https://github.com/statspyml/pyau/issues) and include:

- pyvulscan version (`pip show pyvulscan`)
- Python version (`python --version`)
- OS and version
- The command you ran
- The full output (stdout + stderr)
- Expected vs actual behaviour

---

## Requesting Features

Open an issue with the `enhancement` label. Describe:

- The problem you are trying to solve
- Your proposed solution (if any)
- Any alternatives you considered

Feature requests are prioritised based on alignment with the project's scope — vulnerability auditing for Python dependencies via the OSV API.

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**

Report them privately by emailing rodrigo.pp.toledo@gmail.com with:

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

You will receive a response within 72 hours.

---

## Release Process

Releases are managed exclusively by the maintainer. The process is:

1. All changes land on `main` via merged Pull Requests
2. The maintainer decides when to cut a release based on accumulated changes
3. From `main`, the maintainer runs:

```bash
make bump   # increments patch version, commits, and creates a git tag
make push   # pushes commits and tags to GitHub
```

4. The `publish` GitHub Actions workflow triggers automatically on the new tag, runs the test suite, and publishes to PyPI if tests pass

> **Important:** tags must always be created on `main`. Creating a tag on a feature branch will cause the publish workflow to fail by design.

### Versioning

This project follows [Semantic Versioning](https://semver.org/):

| Change | Version bump |
|---|---|
| Bug fixes, small improvements | `patch` — `0.1.x` |
| New features, backward-compatible | `minor` — `0.x.0` |
| Breaking changes | `major` — `x.0.0` |
