import re
import sys
from pathlib import Path

from pyau.parsers.utils import load_toml, normalise_name


def parse_pyproject_toml(path: Path) -> list[dict]:
    """Parse a pyproject.toml directly (no lockfile).
    Supports PEP 621 [project] and Poetry classic [tool.poetry] formats.
    Uses declared version ranges — less accurate than a lockfile.
    """
    data = load_toml(path)
    packages = []

    # ── PEP 621 ──────────────────────────────────────────────────────────
    pep621_deps = data.get("project", {}).get("dependencies", [])
    if pep621_deps:
        print("  Format: PEP 621 [project]")
        for dep_str in pep621_deps:
            match = re.match(
                r"^([A-Za-z0-9_\-]+)(?:\[.*?\])?\s*[\(\s]*[><=!~]*\s*(\d+\.\d+(?:\.\d+)*)",
                dep_str.strip(),
            )
            if match:
                packages.append({
                    "name": match.group(1),
                    "version": match.group(2),
                    "groups": ["main"],
                })
            else:
                bare = re.match(r"^([A-Za-z0-9_\-]+)", dep_str.strip())
                if bare:
                    print(
                        f"  [WARN] Skipping '{bare.group(1)}' — could not resolve version.",
                        file=sys.stderr,
                    )

    # ── Poetry classic ────────────────────────────────────────────────────
    poetry_section = data.get("tool", {}).get("poetry", {})
    dep_sections = {
        "dependencies": poetry_section.get("dependencies", {}),
        "dev-dependencies": poetry_section.get("dev-dependencies", {}),
        **{
            f"group:{name}": group.get("dependencies", {})
            for name, group in poetry_section.get("group", {}).items()
        },
    }

    if any(dep_sections.values()):
        print("  Format: Poetry classic [tool.poetry]")
        for section, deps in dep_sections.items():
            for pkg_name, spec in deps.items():
                if pkg_name.lower() == "python":
                    continue
                version = None
                if isinstance(spec, str):
                    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", spec)
                    if m:
                        version = m.group(1)
                elif isinstance(spec, dict):
                    m = re.search(r"(\d+\.\d+(?:\.\d+)*)", spec.get("version", ""))
                    if m:
                        version = m.group(1)
                if version:
                    packages.append({"name": pkg_name, "version": version, "groups": [section]})
                else:
                    print(
                        f"  [WARN] Skipping '{pkg_name}' in [{section}] — could not resolve version.",
                        file=sys.stderr,
                    )

    if not packages:
        print(
            "  [WARN] No dependencies found. "
            "Expected [project].dependencies (PEP 621) or [tool.poetry.dependencies].",
            file=sys.stderr,
        )

    return packages


def parse_poetry_lock(
    path: Path,
    groups: list[str] | None = None,
    direct_names: set[str] | None = None,
) -> list[dict]:
    """Parse a poetry.lock file — exact resolved versions.

    Args:
        path:         Path to poetry.lock
        groups:       Only include packages in these groups. Defaults to ["main"].
        direct_names: If set, only include packages whose normalised name is here.

    """
    data = load_toml(path)
    active_groups = set(groups) if groups else {"main"}

    packages = []
    for pkg in data.get("package", []):
        name = pkg.get("name")
        version = pkg.get("version")
        pkg_groups = set(pkg.get("groups", ["main"]))

        if not name or not version:
            print(f"  [WARN] Skipping malformed entry: {pkg}", file=sys.stderr)
            continue

        if not pkg_groups.intersection(active_groups):
            continue

        if direct_names is not None:
            if normalise_name(name) not in direct_names:
                continue

        packages.append({"name": name, "version": version, "groups": sorted(pkg_groups)})

    return packages
