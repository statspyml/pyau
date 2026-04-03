import re
import sys
from pathlib import Path


def parse_requirements_txt(path: Path) -> list[dict]:
    """Parse a requirements.txt file and return a list of {name, version} dicts.
    Handles:
      - name==version
      - name>=version (uses the first version found)
      - Comments, blank lines, and options (-r, -i, --index-url)
      - Extras like package[extra]==version
    """
    packages = []
    for line in path.read_text().splitlines():
        line = line.strip()

        if not line or line.startswith("#") or line.startswith("-"):
            continue

        line = line.split("#")[0].strip()

        match = re.match(
            r"^([A-Za-z0-9_\-]+)(?:\[.*?\])?[><=!~]+\s*([^\s,;]+)",
            line,
        )
        if match:
            name, version = match.group(1), match.group(2)
            packages.append({"name": name, "version": version, "groups": ["main"]})
        else:
            bare_match = re.match(r"^([A-Za-z0-9_\-]+)", line)
            if bare_match:
                print(
                    f"  [WARN] Skipping '{bare_match.group(1)}' — no version pinned.",
                    file=sys.stderr,
                )

    return packages
