from pathlib import Path

from pyau.parsers.utils import load_toml, normalise_name


def parse_uv_lock(
    path: Path,
    direct_names: set[str] | None = None,
) -> list[dict]:
    """Parse a uv.lock file — exact resolved versions.

    uv.lock differences vs poetry.lock:
      - No `groups` field per package
      - Packages with source = { editable/path/git } are local — skip them
      - The project itself appears as source = { editable = "." }

    Args:
        path:         Path to uv.lock
        direct_names: If set, only include packages whose normalised name is here.

    """
    data = load_toml(path)

    packages = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        source = pkg.get("source", {})

        # Skip local/editable/git deps — not auditable PyPI packages
        if "editable" in source or "path" in source or "git" in source:
            continue

        if not name or not version:
            continue

        if direct_names is not None:
            if normalise_name(name) not in direct_names:
                continue

        packages.append({"name": name, "version": version, "groups": ["main"]})

    return packages
