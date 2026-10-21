"""The repository itself must not contain characters the text rules refuse.

Invisible and look-alike characters in source code or docs can hide what code does (the
"Trojan Source" problem). Tests that need such characters write them as escapes.
"""

from __future__ import annotations

import unicodedata
from pathlib import Path

from zoeymcp.common.textrules import INVISIBLE_CHARACTERS, REJECTED_CATEGORIES

ROOT = Path(__file__).resolve().parents[2]
SKIP_DIRS = {
    ".git",
    ".venv",
    "venv",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".hypothesis",
    "mutants",
}
TEXT_SUFFIXES = {
    ".py",
    ".md",
    ".yaml",
    ".yml",
    ".toml",
    ".txt",
    ".cfg",
    ".ini",
    ".json",
    ".lock",
    ".sh",
    ".html",
    ".css",
    ".js",
}
TEXT_NAMES = {"LICENSE", ".gitignore", ".gitattributes", "Dockerfile"}
ALLOWED_CONTROLS = {"\n", "\t"}


def _text_files() -> list[Path]:
    files = []
    for path in ROOT.rglob("*"):
        if any(part in SKIP_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.is_file() and (path.suffix in TEXT_SUFFIXES or path.name in TEXT_NAMES):
            files.append(path)
    return sorted(files)


def test_there_are_files_to_scan() -> None:
    names = {p.name for p in _text_files()}
    assert {"pyproject.toml", "README.md", "LICENSE", "textrules.py"} <= names


def test_no_hidden_characters_in_the_repository() -> None:
    problems = []
    for path in _text_files():
        text = path.read_bytes().decode("utf-8", "surrogatepass")
        line = 1
        for char in text:
            if char == "\n":
                line += 1
                continue
            if char in ALLOWED_CONTROLS:
                continue
            category = unicodedata.category(char)
            if char in INVISIBLE_CHARACTERS or category in REJECTED_CATEGORIES:
                name = unicodedata.name(char, "unnamed")
                problems.append(f"{path.relative_to(ROOT)}:{line}: U+{ord(char):04X} {name}")
    assert problems == []


def test_source_uses_fullmatch_not_match() -> None:
    # "$" also matches before a final line break, so a whole-value check written with .match lets
    # one through (register D-138). Every pattern under src/zoeymcp is used with fullmatch; this
    # catches re.match( too. netguard's lookup is named listed for this reason (M7 design B.1).
    package = ROOT / "src" / "zoeymcp"
    found = []
    for path in sorted(package.rglob("*.py")):
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if ".match(" in line:
                found.append(f"{path.relative_to(ROOT).as_posix()}:{number}")
    assert found == []
