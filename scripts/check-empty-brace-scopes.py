#!/usr/bin/env python3
"""Reject standalone C scope blocks used only to limit variable lifetime."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path


C_EXTENSIONS = {".c", ".h"}
SKIP_DIRS = {
    ".git",
    ".github",
    ".dSYM",
    "__pycache__",
    "build",
    "builddir",
    "cmake-build-debug",
    "cmake-build-release",
    "Debug",
    "Release",
}

BRACE_LINE = re.compile(r"^\s*\{\s*(?://.*|/\*.*\*/\s*)?$")
CONTROL_PREFIX = re.compile(
    r"^(?:\}\s*)?(?:else\b(?:\s+if\b)?|if\b|for\b|while\b|switch\b|do\b)"
)
TYPE_PREFIX = re.compile(r"^(?:typedef\s+)?(?:struct|union|enum)\b")
ALLOW_EXCEPTION = re.compile(r"empty-brace-scan:\s*allow\s*-\s*\S")
TRAILING_BLOCK_COMMENT = re.compile(r"\s*/\*.*?\*/\s*$")


def strip_line_comment(line: str) -> str:
    """Remove simple // comments without trying to parse C strings."""
    stripped = line.split("//", 1)[0].strip()
    while TRAILING_BLOCK_COMMENT.search(stripped):
        stripped = TRAILING_BLOCK_COMMENT.sub("", stripped).strip()
    return stripped


def is_comment_only(line: str) -> bool:
    stripped = line.strip()
    return (
        stripped.startswith("/*")
        or stripped.startswith("* ")
        or stripped.startswith("*\t")
        or stripped == "*"
        or stripped == "*/"
    )


def has_allow_exception(lines: list[str], index: int) -> bool:
    if ALLOW_EXCEPTION.search(lines[index]):
        return True

    for prev_index in range(index - 1, max(index - 4, -1), -1):
        stripped = lines[prev_index].strip()
        if not stripped:
            return False
        if ALLOW_EXCEPTION.search(stripped):
            return True
        if not is_comment_only(stripped):
            return False

    return False


def previous_code_line(lines: list[str], index: int) -> tuple[int, str] | None:
    """Return the previous non-empty, non-preprocessor code line."""
    for prev_index in range(index - 1, -1, -1):
        if is_comment_only(lines[prev_index]):
            continue
        stripped = strip_line_comment(lines[prev_index])
        if not stripped:
            continue
        if stripped.startswith("#"):
            continue
        return prev_index + 1, stripped
    return None


def is_allowed_open_brace(previous: str | None) -> bool:
    if previous is None:
        return True

    if CONTROL_PREFIX.match(previous):
        return True
    if previous.startswith("case ") or previous.startswith("default:"):
        return True
    if TYPE_PREFIX.match(previous):
        return True

    # Function definitions and multi-line control headers normally end in ')'
    # on the line before the opening brace. Function calls end in ');' instead.
    if previous.endswith(")") and not previous.endswith(");"):
        return True

    # Aggregate initializers and macro continuations can place the brace alone.
    if previous.endswith(("{", "=", ",", "(", "[", "\\")):
        return True

    return False


def iter_c_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []

    for path in paths:
        if not path.exists():
            continue
        if path.is_file():
            if path.suffix in C_EXTENSIONS:
                files.append(path)
            continue

        for root, dirs, names in os.walk(path):
            dirs[:] = [
                d for d in dirs
                if d not in SKIP_DIRS and not d.endswith(".dSYM")
            ]
            for name in names:
                candidate = Path(root) / name
                if candidate.suffix in C_EXTENSIONS:
                    files.append(candidate)

    return sorted(set(files))


def scan_file(path: Path) -> list[tuple[Path, int, int, str | None]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(encoding="latin-1").splitlines()

    findings: list[tuple[Path, int, int, str | None]] = []
    for index, line in enumerate(lines):
        if not BRACE_LINE.match(line):
            continue
        previous = previous_code_line(lines, index)
        previous_text = previous[1] if previous else None
        if is_allowed_open_brace(previous_text):
            continue
        if has_allow_exception(lines, index):
            continue
        column = line.index("{") + 1
        findings.append((path, index + 1, column, previous_text))

    return findings


def emit_finding(path: Path, line: int, column: int, previous: str | None) -> None:
    message = (
        "standalone scope block is not allowed; if truly required, add "
        "'empty-brace-scan: allow - <reason>' directly above the brace"
    )
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::error file={path},line={line},col={column}::{message}")
    print(f"{path}:{line}:{column}: {message}")
    if previous:
        print(f"  previous code: {previous}")


def main(argv: list[str]) -> int:
    roots = [Path(arg) for arg in argv] if argv else [
        Path("src"),
        Path("wolftpm"),
        Path("tests"),
        Path("examples"),
        Path("hal"),
        Path("IDE"),
        Path("zephyr"),
    ]
    files = iter_c_files(roots)
    findings: list[tuple[Path, int, int, str | None]] = []
    for path in files:
        findings.extend(scan_file(path))

    if findings:
        print("Bare C scope block(s) found. Use normal control flow and cleanup at the end of the function instead.")
        for finding in findings:
            emit_finding(*finding)
        return 1

    print(f"OK: scanned {len(files)} C source/header file(s); no bare scope blocks found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
