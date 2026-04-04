"""Multiscan: scan multiple projects from a config file."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from pyau.osv.client import query_osv_batch
from pyau.osv.processor import process_results
from pyau.parsers import detect_and_parse

# Dependency files searched in priority order (highest priority first)
_DEP_FILE_PRIORITY = ["uv.lock", "poetry.lock", "pyproject.toml", "requirements.txt"]


# ── config loading ────────────────────────────────────────────────────────────

def load_config(config_path: str) -> list[dict]:
    """Load a multiscan config file and return a list of project dicts.

    Each project dict has at least a 'path' key, and an optional 'name' key.

    Supported formats:
      - JSON  (.json)
      - YAML  (.yaml / .yml) — requires PyYAML
      - Python (.py)         — must define a top-level ``projects`` list
    """
    path = Path(config_path)
    if not path.exists():
        print(f"Error: Config file not found: {config_path}", file=sys.stderr)
        sys.exit(1)

    suffix = path.suffix.lower()

    if suffix == ".json":
        raw = _load_json(path)
    elif suffix in (".yaml", ".yml"):
        raw = _load_yaml(path)
    elif suffix == ".py":
        raw = _load_python(path)
    else:
        print(
            f"Error: Unsupported config format '{suffix}'. "
            "Use .json, .yaml/.yml, or .py",
            file=sys.stderr,
        )
        sys.exit(1)

    return _normalise_projects(raw, config_path)


def _load_json(path: Path) -> object:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _load_yaml(path: Path) -> object:
    try:
        import yaml  # type: ignore[import-untyped]
    except ImportError:
        print(
            "Error: PyYAML is required to read .yaml/.yml config files.\n"
            "Install it with:  pip install pyyaml",
            file=sys.stderr,
        )
        sys.exit(1)
    with path.open(encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def _load_python(path: Path) -> object:
    spec = importlib.util.spec_from_file_location("_multiscan_cfg", path)
    if spec is None or spec.loader is None:
        print(f"Error: Cannot load Python config from {path}", file=sys.stderr)
        sys.exit(1)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    if not hasattr(module, "projects"):
        print(
            f"Error: Python config {path} must define a top-level 'projects' list.",
            file=sys.stderr,
        )
        sys.exit(1)
    return module.projects


def _normalise_projects(raw: object, config_path: str) -> list[dict]:
    """Accept both list-of-strings and list-of-dicts; also unwrap {projects: [...]}."""
    if isinstance(raw, dict):
        raw = raw.get("projects", [])

    if not isinstance(raw, list):
        print(
            f"Error: Config '{config_path}' must contain a list of projects.",
            file=sys.stderr,
        )
        sys.exit(1)

    projects: list[dict] = []
    for item in raw:
        if isinstance(item, str):
            projects.append({"path": item, "name": None})
        elif isinstance(item, dict):
            if "path" not in item:
                print(
                    f"Error: Each project entry must have a 'path' key. Got: {item}",
                    file=sys.stderr,
                )
                sys.exit(1)
            projects.append({"path": item["path"], "name": item.get("name")})
        else:
            print(
                f"Error: Unexpected project entry type {type(item).__name__}: {item}",
                file=sys.stderr,
            )
            sys.exit(1)

    return projects


# ── scan logic ────────────────────────────────────────────────────────────────

def find_dep_file(directory: str) -> Path | None:
    """Return the highest-priority dependency file found in *directory*, or None."""
    dir_path = Path(directory).expanduser()
    for name in _DEP_FILE_PRIORITY:
        candidate = dir_path / name
        if candidate.exists():
            return candidate
    return None


def scan_project(project: dict) -> dict:
    """Scan a single project directory.

    Returns a result dict with keys:
      path, name, dep_file, packages_scanned, vulnerabilities_found, findings, error
    """
    directory = project["path"]
    name = project["name"] or Path(directory).name

    dir_path = Path(directory).expanduser()
    if not dir_path.exists():
        return _error_result(name, directory, f"Directory not found: {directory}")
    if not dir_path.is_dir():
        return _error_result(name, directory, f"Path is not a directory: {directory}")

    dep_file = find_dep_file(str(dir_path))
    if dep_file is None:
        return _error_result(
            name,
            directory,
            "No dependency file found (uv.lock, poetry.lock, pyproject.toml, requirements.txt)",
        )

    packages = detect_and_parse(str(dep_file))
    if not packages:
        return {
            "name": name,
            "path": directory,
            "dep_file": str(dep_file),
            "packages_scanned": 0,
            "vulnerabilities_found": 0,
            "findings": [],
            "error": None,
        }

    results = query_osv_batch(packages)
    findings = process_results(packages, results)

    return {
        "name": name,
        "path": directory,
        "dep_file": str(dep_file),
        "packages_scanned": len(packages),
        "vulnerabilities_found": len(findings),
        "findings": findings,
        "error": None,
    }


def run_multiscan(projects: list[dict]) -> list[dict]:
    """Scan all projects and return a list of per-project result dicts."""
    scan_results = []
    for i, project in enumerate(projects, 1):
        label = project.get("name") or Path(project["path"]).name
        print(f"\n[{i}/{len(projects)}] Scanning: {label}  ({project['path']})")
        result = scan_project(project)
        if result["error"]:
            print(f"  ! Error: {result['error']}")
        else:
            print(
                f"  Packages: {result['packages_scanned']}  "
                f"Vulnerabilities: {result['vulnerabilities_found']}"
            )
        scan_results.append(result)
    return scan_results


# ── helpers ───────────────────────────────────────────────────────────────────

def _error_result(name: str, path: str, error: str) -> dict:
    return {
        "name": name,
        "path": path,
        "dep_file": None,
        "packages_scanned": 0,
        "vulnerabilities_found": 0,
        "findings": [],
        "error": error,
    }
