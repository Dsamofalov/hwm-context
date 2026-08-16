#!/usr/bin/env python3
"""Repository Bootstrap CI validation for canonical I09 task-context artifacts."""
from __future__ import annotations

import os
import re
import stat
import sys
from pathlib import Path

from publisher.task_context_contract import Reject, validate_pack_bytes

TASK_DIRECTORY_RE = re.compile(r"^I[0-9]{2}-[0-9]{4}$")


def validate_repository(root: Path) -> None:
    tasks = root / "tasks"
    if not tasks.is_dir():
        raise Reject("PACK_INVALID", "tasks directory is missing")
    for path in tasks.rglob("*"):
        if path.is_dir():
            continue
        relative = path.relative_to(tasks).as_posix()
        if relative == ".gitkeep":
            continue
        parts = relative.split("/")
        if len(parts) != 2 or TASK_DIRECTORY_RE.fullmatch(parts[0]) is None or parts[1] != "context.json":
            raise Reject("FORBIDDEN_PATH", "noncanonical task artifact is present")
        if path.is_symlink() or not path.is_file():
            raise Reject("BLOB_NOT_REGULAR", "task-context artifact is not a regular file")
        mode = os.stat(path, follow_symlinks=False).st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise Reject("BLOB_NOT_REGULAR", "task-context artifact is executable")
        validate_pack_bytes(path.read_bytes(), expected_task_key=parts[0])


def main(argv: list[str]) -> int:
    try:
        validate_repository(Path(argv[1] if len(argv) > 1 else "."))
    except Reject as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
