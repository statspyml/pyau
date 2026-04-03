import sys
from pathlib import Path

from pyau.parsers.poetry import parse_poetry_lock, parse_pyproject_toml
from pyau.parsers.requirements import parse_requirements_txt
from pyau.parsers.utils import direct_names_from_pyproject
from pyau.parsers.uv import parse_uv_lock


def detect_and_parse(
    file_path: str,
    groups: list[str] | None = None,
    direct_only: bool = False,
) -> list[dict]:
    """Detect the dependency file type and parse it.

    Priority when pyproject.toml is given:
        uv.lock > poetry.lock > pyproject.toml (ranges only)
    """
    path = Path(file_path)
    if not path.exists():
        print(f"Error: File not found: {file_path}", file=sys.stderr)
        sys.exit(1)

    # ── uv.lock ───────────────────────────────────────────────────────────
    if path.name == "uv.lock":
        return _parse_uv(path, direct_only)

    # ── poetry.lock ───────────────────────────────────────────────────────
    if path.name == "poetry.lock":
        return _parse_poetry(path, groups, direct_only)

    # ── pyproject.toml ────────────────────────────────────────────────────
    if path.name == "pyproject.toml":
        uv_lock = path.parent / "uv.lock"
        poetry_lock = path.parent / "poetry.lock"

        if uv_lock.exists():
            return _parse_uv(uv_lock, direct_only, pyproject=path)
        if poetry_lock.exists():
            return _parse_poetry(poetry_lock, groups, direct_only, pyproject=path)

        print("Detected: pyproject.toml (no lockfile found, using declared version ranges)")
        return parse_pyproject_toml(path)

    # ── requirements.txt ──────────────────────────────────────────────────
    if path.name.endswith(".txt") or "requirements" in path.name.lower():
        print("Detected: requirements.txt")
        return parse_requirements_txt(path)

    print(
        f"Error: Unrecognised file '{path.name}'. "
        "Expected uv.lock, poetry.lock, pyproject.toml, or requirements.txt.",
        file=sys.stderr,
    )
    sys.exit(1)


# ── helpers ───────────────────────────────────────────────────────────────────

def _resolve_direct_names(
    lock_path: Path,
    direct_only: bool,
    pyproject: Path | None = None,
) -> set[str] | None:
    """Return direct dep names if --direct-only, else None."""
    if not direct_only:
        return None

    pyproject = pyproject or (lock_path.parent / "pyproject.toml")
    if pyproject.exists():
        names = direct_names_from_pyproject(pyproject)
        print(f"  direct-only mode ({len(names)} direct deps)")
        return names

    print("  [WARN] --direct-only requested but no pyproject.toml found — auditing all")
    return None


def _parse_uv(
    path: Path,
    direct_only: bool,
    pyproject: Path | None = None,
) -> list[dict]:
    direct_names = _resolve_direct_names(path, direct_only, pyproject)
    label = "direct-only" if direct_names is not None else "all resolved packages"
    print(f"Detected: uv.lock ({label})")
    return parse_uv_lock(path, direct_names=direct_names)


def _parse_poetry(
    path: Path,
    groups: list[str] | None,
    direct_only: bool,
    pyproject: Path | None = None,
) -> list[dict]:
    direct_names = _resolve_direct_names(path, direct_only, pyproject)
    label = "direct-only" if direct_names is not None else "all resolved packages"
    print(f"Detected: poetry.lock ({label})")
    return parse_poetry_lock(path, groups=groups, direct_names=direct_names)
