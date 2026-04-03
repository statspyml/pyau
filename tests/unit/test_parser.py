"""Unit tests for the parsers module.
Run with: uv run pytest tests/
"""
import textwrap
from pathlib import Path

from pyau.parsers.requirements import parse_requirements_txt
from pyau.parsers.utils import direct_names_from_pyproject, normalise_name

# ── requirements.txt ──────────────────────────────────────────────────────────

def test_parse_requirements_pinned(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\nflask>=2.0.0\n")
    packages = parse_requirements_txt(req)
    assert len(packages) == 2
    assert packages[0] == {"name": "requests", "version": "2.31.0", "groups": ["main"]}
    assert packages[1]["name"] == "flask"
    assert packages[1]["version"] == "2.0.0"


def test_parse_requirements_skips_comments(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("# this is a comment\nrequests==2.31.0\n")
    packages = parse_requirements_txt(req)
    assert len(packages) == 1


def test_parse_requirements_skips_options(tmp_path: Path):
    req = tmp_path / "requirements.txt"
    req.write_text("-r other.txt\n--index-url https://pypi.org\nrequests==2.31.0\n")
    packages = parse_requirements_txt(req)
    assert len(packages) == 1


# ── utils ─────────────────────────────────────────────────────────────────────

def test_normalise_name():
    assert normalise_name("Flask") == "flask"
    assert normalise_name("my-package") == "my_package"
    assert normalise_name("My_Package") == "my_package"


def test_direct_names_pep621(tmp_path: Path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(textwrap.dedent("""
        [project]
        name = "myapp"
        dependencies = [
            "requests>=2.28",
            "tornado==6.5.4",
        ]
    """))
    names = direct_names_from_pyproject(pyproject)
    assert "requests" in names
    assert "tornado" in names
    assert "python" not in names
