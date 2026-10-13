"""The documentation must reflect the code, never the other way around."""
import os
import re
from pathlib import Path

from ssm_manager import CONFIG

ROOT = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "AGENTS.md")
CONFIG_PATH_RE = re.compile(r"~/\.[A-Za-z0-9_]+")


def _documented_config_paths():
    paths = set()
    for name in DOCS:
        paths |= set(CONFIG_PATH_RE.findall((ROOT / name).read_text(encoding="utf-8")))
    return paths


def test_documentation_matches_config_default():
    documented = _documented_config_paths()
    expected = {"~/" + os.path.basename(CONFIG["default_config_file"])}
    assert documented == expected, (
        f"documentation documents {sorted(documented)} but the code default is "
        f"{sorted(expected)}. The code is the source of truth: fix the documentation, "
        "not the behavior."
    )
