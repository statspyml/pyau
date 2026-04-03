# pyvulscan

Vulnerability scanner for Python dependencies using the [OSV API](https://osv.dev/).

Supports `uv.lock`, `poetry.lock`, `pyproject.toml`, and `requirements.txt` — no environment activation needed.

## Install

```bash
pip install pyvulscan
```

## Usage

```bash
# Auto-detect lockfile in current project
pyvulscan pyproject.toml

# Scan only direct dependencies (not transitive)
pyvulscan pyproject.toml --direct-only

# Scan a specific lockfile
pyvulscan uv.lock
pyvulscan poetry.lock

# JSON output (for CI/CD integration)
pyvulscan pyproject.toml --json

# Exit with code 1 if vulnerabilities found (CI gate)
pyvulscan pyproject.toml --exit-code

# Include dev dependencies (Poetry only)
pyvulscan pyproject.toml --group main --group dev
```

## How it works

1. Parses your lockfile to get exact resolved versions
2. Sends a single batch request to the OSV API
3. Fetches full details (severity, fix version) for each vulnerability found
4. Reports findings with CVSS score, label, and recommended fix version

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint
ruff check src/
```
