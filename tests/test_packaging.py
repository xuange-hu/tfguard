"""Packaging contract tests.

The console scripts are the only thing a user touches, so the modules they point
at must import with base dependencies alone. CI installs ``.[mcp]`` and would
therefore never notice an optional import leaking into a required path.

On Python 3.10 ``tomllib`` does not exist, so the reader falls back to
``tests/_pytoml.py`` instead of skipping: a guard that quietly switches itself
off is worse than no guard.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python <= 3.10: tomllib landed in 3.11
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import _pytoml as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
SRC = ROOT / "src"


def _config() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def test_version_matches_the_package():
    import tfguard

    assert tfguard.__version__ == _config()["project"]["version"]


def test_console_scripts_resolve():
    scripts = _config()["project"]["scripts"]
    assert "tfguard" in scripts
    assert "tfguard-mcp" in scripts
    for target in scripts.values():
        module, _, attr = target.partition(":")
        assert module.startswith("tfguard.")
        assert attr


def test_core_modules_import_without_the_mcp_extra():
    for name in (
        "tfguard.analyze",
        "tfguard.cli",
        "tfguard.demo",
        "tfguard.hcl",
        "tfguard.loader",
        "tfguard.model",
        "tfguard.render",
        "tfguard.rules",
        "tfguard.sarif",
    ):
        assert importlib.import_module(name) is not None


def test_the_mcp_module_is_importable_but_lazy():
    """``tfguard.mcp_server`` must not import ``mcp`` at module scope."""
    import tfguard.mcp_server as m

    assert callable(m.build_server)
    assert m.tool_manifest()


def test_no_optional_import_outside_the_mcp_module():
    offenders = []
    for path in sorted(SRC.joinpath("tfguard").glob("*.py")):
        if path.name == "mcp_server.py":
            continue
        text = path.read_text(encoding="utf-8")
        for match in re.finditer(r"^\s*(?:from|import)\s+([a-z_][\w.]*)", text, re.MULTILINE):
            top = match.group(1).split(".")[0]
            if top == "mcp":
                offenders.append(f"{path.name}: {match.group(0).strip()}")
    assert offenders == [], offenders


def test_zero_declared_dependencies():
    assert _config()["project"]["dependencies"] == []


def test_mcp_is_an_extra_not_a_dependency():
    assert "mcp" in _config()["project"]["optional-dependencies"]


def test_python_floor_is_310():
    assert _config()["project"]["requires-python"] == ">=3.10"


def test_src_layout_is_declared():
    assert _config()["tool"]["setuptools"]["packages"]["find"]["where"] == ["src"]


def test_every_source_module_is_importable():
    import tfguard

    pkg = Path(tfguard.__file__).parent
    for path in sorted(pkg.glob("*.py")):
        if path.name == "mcp_server.py":
            continue
        assert importlib.import_module(f"tfguard.{path.stem}") is not None


def test_readme_is_the_declared_readme():
    assert _config()["project"]["readme"] == "README.md"
    assert (ROOT / "README.md").is_file()
