"""Fix: Automatically change libs with vuln in the pyproject/requirement file"""

import subprocess
from pathlib import Path

from packaging.version import Version


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
        "uv": ["uv", "add", pkg_spec, "--dry-run"],
        "poetry": ["poetry", "add", pkg_spec, "--dry-run"],
        "pip": ["pip", "install", pkg_spec, "--dry-run"],
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
    # TODO:
