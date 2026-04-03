import sys
from pathlib import Path


def load_toml(path: Path) -> dict:
    """Load a TOML file using tomllib (3.11+) or tomli as fallback."""
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            print(
                "Error: requires Python 3.11+ or 'tomli'.\n"
                "Install with: pip install tomli",
                file=sys.stderr,
            )
            sys.exit(1)

    with path.open("rb") as f:
        return tomllib.load(f)


def normalise_name(name: str) -> str:
    """Normalise a package name: lowercase + hyphens to underscores."""
    return name.lower().replace("-", "_")


def direct_names_from_pyproject(pyproject_path: Path) -> set[str]:
    """Extract directly declared dependency names from pyproject.toml.
    Supports PEP 621 [project] and Poetry classic [tool.poetry] formats.
    Returns normalised names (lowercase, hyphens → underscores).
    """
    data = load_toml(pyproject_path)
    names: set[str] = set()

    # PEP 621 / uv format
    import re
    for dep_str in data.get("project", {}).get("dependencies", []):
        m = re.match(r"^([A-Za-z0-9_\-]+)", dep_str.strip())
        if m:
            names.add(normalise_name(m.group(1)))

    # Poetry classic format
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name in poetry_deps:
        if name.lower() != "python":
            names.add(normalise_name(name))

    return names
