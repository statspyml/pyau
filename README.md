# pyvulscan

[![Tests](https://github.com/statspyml/pyau/actions/workflows/test.yml/badge.svg)](https://github.com/statspyml/pyau/actions/workflows/test.yml)
[![PyPI](https://img.shields.io/pypi/v/pyvulscan)](https://pypi.org/project/pyvulscan/)
[![Python](https://img.shields.io/pypi/pyversions/pyvulscan)](https://pypi.org/project/pyvulscan/)
[![License](https://img.shields.io/github/license/statspyml/pyau)](LICENSE)
[![Downloads](https://img.shields.io/pypi/dm/pyvulscan)](https://pypi.org/project/pyvulscan/)

Vulnerability scanner for Python dependencies using the [OSV API](https://osv.dev/).

Supports `uv.lock`, `poetry.lock`, `pyproject.toml`, and `requirements.txt` — no environment activation needed.

## Install

```bash
pip install pyvulscan
```

## Usage

### Single project

```bash
# Auto-detect lockfile in current project
pyvulscan pyproject.toml

# Scan a specific lockfile
pyvulscan uv.lock
pyvulscan poetry.lock

# Scan only direct dependencies (not transitive)
pyvulscan pyproject.toml --direct-only

# Include dev dependencies (Poetry only)
pyvulscan pyproject.toml --group main --group dev

# JSON output (for CI/CD integration)
pyvulscan pyproject.toml --json

# Exit with code 1 if vulnerabilities found (CI gate)
pyvulscan pyproject.toml --exit-code

# Add a filtered summary section at the end (HIGH and CRITICAL only)
pyvulscan pyproject.toml --filter HIGH

# Filter from MEDIUM and above
pyvulscan pyproject.toml --filter MEDIUM
```

### Multiple projects (multiscan)

Scan several projects at once from a config file. All projects are scanned in parallel and findings are grouped by project in the report.

```bash
pyvulscan multiscan projects.json
pyvulscan multiscan projects.yaml
pyvulscan multiscan projects.py

# JSON output
pyvulscan multiscan projects.json --json

# CI gate: exit 1 if any project has vulnerabilities
pyvulscan multiscan projects.json --exit-code

# Add a filtered summary section grouped by project (HIGH and CRITICAL only)
pyvulscan multiscan projects.json --filter HIGH
```

#### Config file formats

All formats accept a simple list of paths or a list of objects with `path` and an optional `name`.

**JSON** (`projects.json`):
```json
{
  "projects": [
    { "path": "~/code/api", "name": "API" },
    { "path": "~/code/workers" }
  ]
}
```

**YAML** (`projects.yaml`) — requires `pip install pyyaml`:
```yaml
projects:
  - path: ~/code/api
    name: API
  - path: ~/code/workers
```

**Python** (`projects.py`):
```python
projects = [
    {"path": "~/code/api", "name": "API"},
    {"path": "~/code/workers"},
]
```

Example files are available in the repository root: `multiscan.example.json`, `multiscan.example.yaml`, `multiscan.example.py`.

### Severity filter

The `--filter LEVEL` option appends a dedicated section at the end of the report listing only findings at or above the chosen severity. The full report is always shown — the filter section is additive.

Accepted levels (from lowest to highest): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.

Without `--filter`, the section is omitted. Works in both single-project and multiscan modes; in multiscan, findings are grouped by project inside the filter section.

## How it works

1. Parses your lockfile to get exact resolved versions
2. Sends a single batch request to the OSV API
3. Fetches full details (severity, fix version) for each vulnerability found **in parallel**
4. Reports findings with CVSS score, label, and recommended fix version

In multiscan mode, all projects are also scanned in parallel.

---

## MCP Server

pyvulscan includes an [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that lets Claude Code scan for vulnerabilities directly, without leaving the chat.

### Install with MCP support

```bash
pip install pyvulscan[mcp]

# or with pipx
pipx install pyvulscan[mcp]

# or with uv
uv tool install pyvulscan[mcp]
```

### Configure Claude Code

**Project-level** — create `.mcp.json` in your project root (recommended):

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "pyvulscan-mcp"
    }
  }
}
```

**Global CLI** — add once and use across all projects:

```bash
claude mcp add pyvulscan pyvulscan-mcp
```

**Claude Desktop** — edit `~/.config/claude/claude_desktop_config.json` (macOS/Linux) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "pyvulscan-mcp"
    }
  }
}
```

**Without installing** — use `uvx`:

```json
{
  "mcpServers": {
    "pyvulscan": {
      "command": "uvx",
      "args": ["--from", "pyvulscan[mcp]", "pyvulscan-mcp"]
    }
  }
}
```

Restart Claude Code after any config change.

### Available tools

| Tool | Description |
|---|---|
| `scan_vulnerabilities` | Scan a specific dependency file (`uv.lock`, `poetry.lock`, `pyproject.toml`, `requirements.txt`) |
| `scan_directory` | Auto-detect and scan all dependency files in a directory |
| `check_package` | Check a specific package by name — auto-detects the version from the project if not provided |

**Example prompts:**

```
Scan my current project for vulnerabilities
Check if the requests package has any known vulnerabilities
Scan the file requirements.txt in /path/to/project
```

### Response format

All tools return JSON:

```json
{
  "success": true,
  "packages_scanned": 10,
  "vulnerabilities_found": 2,
  "findings": [
    {
      "package": "django",
      "version": "3.2.0",
      "vuln_id": "GHSA-xxxx-xxxx-xxxx",
      "aliases": ["CVE-2023-12345"],
      "summary": "Description of the vulnerability",
      "severity": { "score": 7.5, "label": "HIGH", "type": "CVSS:3.1" },
      "fixed_versions": ["3.2.19", "4.1.8"]
    }
  ]
}
```

### Troubleshooting

- **Server not appearing** — verify the config file syntax and restart Claude Code completely.
- **Command not found** — confirm the package is installed (`pip list | grep pyvulscan`) or switch to the `uvx` option.
- **Logs** — Claude Code stores MCP logs at `~/.config/claude/logs/` (macOS/Linux) or `%APPDATA%\Claude\logs\` (Windows).

---

## Development

```bash
# Install with dev dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Lint
ruff check src/
```
