"""Fix: Automatically change libs with vuln in the pyproject/requirement file"""

import re
import subprocess
from pathlib import Path

from packaging.version import Version

from pyau.severity import meets_threshold

_HIGH_OR_ABOVE = "HIGH"


def _select_fix_version(current_version: str, fixed_versions: list[str]) -> str | None:
    """Compara a versão atual do pacote com a versão sugerida pelo fix."""
    current = Version(current_version)
    candidates = [v for v in fixed_versions if Version(v) > current]

    if not candidates:
        return None
    return str(min(candidates, key=Version))


def _detect_tool(project_path: str) -> str | None:
    """Detecta qual ferramenta de dependência o projeto usa."""
    path = Path(project_path).expanduser()
    if (path / "uv.lock").exists():
        return "uv"
    if (path / "poetry.lock").exists():
        return "poetry"
    if (path / "requirements.txt").exists():
        return "pip"
    if (path / "pyproject.toml").exists():
        return "pip"
    return None


def _dry_run_fix(tool: str, package: str, fix_version: str) -> dict:
    """Testa se aplicar a versão corrigida resolve sem conflitos."""
    pkg_spec = f"{package}=={fix_version}"

    commands = {
        "uv":     ["uv", "pip", "install", pkg_spec, "--dry-run"],
        "poetry": ["poetry", "add", pkg_spec, "--dry-run"],
        "pip":    ["pip", "install", pkg_spec, "--dry-run"],
    }

    cmd = commands.get(tool)
    if cmd is None:
        return {
            "package": package,
            "fix_version": fix_version,
            "success": False,
            "output": f"Unknown tool: {tool}",
        }

    result = subprocess.run(cmd, capture_output=True, text=True)

    return {
        "package": package,
        "fix_version": fix_version,
        "success": result.returncode == 0,
        "output": result.stdout or result.stderr,
    }


def run_fix(findings: list[dict], project_path: str) -> list[dict]:
    """Orquestra o dry-run de fix para todos os findings."""
    tool = _detect_tool(project_path)
    if tool is None:
        return []

    results = []
    seen = set()

    for finding in findings:
        package = finding["package"]
        current_version = finding["version"]
        fixed_version = finding.get("fixed_versions", [])

        fix_version = _select_fix_version(current_version, fixed_version)
        if fix_version is None:
            results.append(
                {
                    "package": package,
                    "fix_version": None,
                    "success": None,
                    "output": "No fix version available",
                    "tool": tool,
                },
            )
            continue

        key = (package, fix_version)
        if key in seen:
            continue
        seen.add(key)

        result = _dry_run_fix(tool, package, fix_version)
        results.append(result)

    return results


# ── apply fix ─────────────────────────────────────────────────────────────────

def _resolve_manifest(dep_file: Path) -> Path | None:
    """Given a dep file (possibly a lock file), return the manifest to edit."""
    name = dep_file.name
    parent = dep_file.parent
    if name in ("uv.lock", "poetry.lock"):
        manifest = parent / "pyproject.toml"
        return manifest if manifest.exists() else None
    if name in ("pyproject.toml", "requirements.txt"):
        return dep_file
    return None


def _build_fix_map(findings: list[dict]) -> dict[str, str]:
    """Return {normalized_name: best_fix_version} for HIGH/CRITICAL findings only."""
    per_package: dict[str, list[str]] = {}
    for finding in findings:
        if not meets_threshold(finding, _HIGH_OR_ABOVE):
            continue
        pkg = finding["package"].lower().replace("-", "_")
        fix = _select_fix_version(finding["version"], finding.get("fixed_versions", []))
        if fix is None:
            continue
        per_package.setdefault(pkg, []).append(fix)

    return {pkg: str(max(versions, key=Version)) for pkg, versions in per_package.items()}


def _apply_to_requirements(path: Path, fix_map: dict[str, str]) -> list[dict]:
    """Edit requirements.txt in-place, preserving operators and comments."""
    lines = path.read_text().splitlines(keepends=True)
    results = []

    _OP_RE = re.compile(
        r"^(?P<name>[A-Za-z0-9_\-]+)(?P<extras>\[.*?\])?"
        r"(?P<op>[><=!~]+)\s*(?P<ver>[^\s,;#]+)",
    )

    new_lines = []
    for line in lines:
        match = _OP_RE.match(line.strip().split("#")[0].strip())
        if match:
            norm = match.group("name").lower().replace("-", "_")
            if norm in fix_map:
                fix_ver = fix_map[norm]
                old_ver = match.group("ver")
                op = match.group("op")
                extras = match.group("extras") or ""
                old_spec = match.group("name") + extras + op + old_ver
                new_spec = match.group("name") + extras + op + fix_ver
                new_line = line.replace(old_spec, new_spec, 1)
                new_lines.append(new_line)
                results.append({
                    "package": match.group("name"),
                    "old_version": old_ver,
                    "new_version": fix_ver,
                    "file": str(path),
                    "applied": True,
                })
                continue
        new_lines.append(line)

    path.write_text("".join(new_lines))
    return results


def _apply_to_pyproject(path: Path, fix_map: dict[str, str]) -> list[dict]:
    """Edit pyproject.toml in-place using text replacement, preserving formatting."""
    text = path.read_text()
    results = []

    # Matches: name = "op version" or name = "version" (Poetry style)
    # Also matches PEP 621: "name op version" inside lists (handled separately)
    _POETRY_DEP_RE = re.compile(
        r'(?P<name>[A-Za-z0-9_\-]+)\s*=\s*"(?P<op>[~^>=<!]*)\s*(?P<ver>[0-9][^\s"]*)"'
    )
    # PEP 621: "name op version" or "name==version" inside a list value
    _PEP621_DEP_RE = re.compile(
        r'"(?P<name>[A-Za-z0-9_\-]+)(?P<extras>\[.*?\])?(?P<op>[><=!~]+)\s*(?P<ver>[0-9][^\s",]+)"'
    )

    def _replace_poetry(m: re.Match) -> str:
        norm = m.group("name").lower().replace("-", "_")
        if norm not in fix_map:
            return m.group(0)
        fix_ver = fix_map[norm]
        old_ver = m.group("ver")
        op = m.group("op")
        results.append({
            "package": m.group("name"),
            "old_version": old_ver,
            "new_version": fix_ver,
            "file": str(path),
            "applied": True,
        })
        return f'{m.group("name")} = "{op}{fix_ver}"'

    def _replace_pep621(m: re.Match) -> str:
        norm = m.group("name").lower().replace("-", "_")
        if norm not in fix_map:
            return m.group(0)
        fix_ver = fix_map[norm]
        old_ver = m.group("ver")
        op = m.group("op")
        extras = m.group("extras") or ""
        results.append({
            "package": m.group("name"),
            "old_version": old_ver,
            "new_version": fix_ver,
            "file": str(path),
            "applied": True,
        })
        return f'"{m.group("name")}{extras}{op}{fix_ver}"'

    new_text = _POETRY_DEP_RE.sub(_replace_poetry, text)
    new_text = _PEP621_DEP_RE.sub(_replace_pep621, new_text)

    path.write_text(new_text)
    return results


def apply_fixes(findings: list[dict], dep_file: str) -> list[dict]:
    """Apply fixes for HIGH/CRITICAL findings to the manifest file.

    Edits pyproject.toml or requirements.txt in-place, preserving operators
    and comments. For lock files (uv.lock, poetry.lock), edits the adjacent
    pyproject.toml.

    Returns a list of result dicts with applied changes and packages with no
    available fix.
    """
    fix_map = _build_fix_map(findings)

    manifest = _resolve_manifest(Path(dep_file))
    if manifest is None:
        return [{"error": f"No editable manifest found for {dep_file}"}]

    if manifest.name == "requirements.txt":
        applied = _apply_to_requirements(manifest, fix_map)
    else:
        applied = _apply_to_pyproject(manifest, fix_map)

    applied_names = {r["package"].lower().replace("-", "_") for r in applied}

    for pkg, fix_ver in fix_map.items():
        if pkg not in applied_names:
            applied.append({
                "package": pkg,
                "old_version": None,
                "new_version": fix_ver,
                "file": str(manifest),
                "applied": False,
                "reason": "Package not found in manifest (may be a transitive dep)",
            })

    no_fix_pkgs: set[str] = set()
    for finding in findings:
        if not meets_threshold(finding, _HIGH_OR_ABOVE):
            continue
        norm = finding["package"].lower().replace("-", "_")
        fix = _select_fix_version(finding["version"], finding.get("fixed_versions", []))
        if fix is None and norm not in {r["package"].lower().replace("-", "_") for r in applied}:
            no_fix_pkgs.add(finding["package"])

    for pkg in no_fix_pkgs:
        applied.append({
            "package": pkg,
            "old_version": None,
            "new_version": None,
            "file": str(manifest),
            "applied": False,
            "reason": "No fix version available upstream",
        })

    tool = _detect_tool(str(manifest.parent))
    lock_hint = None
    if tool == "uv":
        lock_hint = "uv lock"
    elif tool == "poetry":
        lock_hint = "poetry lock"

    return [{"manifest": str(manifest), "lock_hint": lock_hint, "changes": applied}]
