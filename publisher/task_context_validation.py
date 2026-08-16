#!/usr/bin/env python3
"""Repository Bootstrap CI validation for canonical I09 task-context artifacts."""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from publisher.task_context_contract import Reject, validate_pack_bytes

TASK_DIRECTORY_RE = re.compile(r"^I[0-9]{2}-[0-9]{4}$")


def validate_index_entry(git_path: str, mode: str, object_type: str) -> str | None:
    if git_path == "tasks/.gitkeep":
        if mode != "100644" or object_type != "blob":
            raise Reject("BLOB_NOT_REGULAR", "tasks/.gitkeep must remain a regular 100644 blob")
        return None
    prefix = "tasks/"
    if not git_path.startswith(prefix):
        raise Reject("FORBIDDEN_PATH", "task index entry is outside tasks/")
    relative = git_path[len(prefix):]
    parts = relative.split("/")
    if len(parts) != 2 or TASK_DIRECTORY_RE.fullmatch(parts[0]) is None or parts[1] != "context.json":
        raise Reject("FORBIDDEN_PATH", "noncanonical task artifact is present")
    if mode != "100644" or object_type != "blob":
        raise Reject("BLOB_NOT_REGULAR", "task-context artifact must be a regular 100644 Git blob")
    return parts[0]


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise Reject("PACK_INVALID", "task-context Git metadata validation failed")
    return completed.stdout


def _index_entries(root: Path) -> dict[str, tuple[str, str]]:
    entries: dict[str, tuple[str, str]] = {}
    for line in _git(root, "ls-files", "-s", "--", "tasks").splitlines():
        try:
            metadata, git_path = line.split("\t", 1)
            mode, object_id, stage = metadata.split()
        except ValueError as exc:
            raise Reject("PACK_INVALID", "task-context Git index entry is malformed") from exc
        if stage != "0" or git_path in entries:
            raise Reject("PACK_INVALID", "task-context Git index contains unresolved or duplicate entries")
        object_type = _git(root, "cat-file", "-t", object_id).strip()
        validate_index_entry(git_path, mode, object_type)
        entries[git_path] = (mode, object_id)
    return entries


def validate_repository(root: Path) -> None:
    tasks = root / "tasks"
    if not tasks.is_dir():
        raise Reject("PACK_INVALID", "tasks directory is missing")
    entries = _index_entries(root)
    if "tasks/.gitkeep" not in entries:
        raise Reject("PACK_INVALID", "tasks/.gitkeep is missing")

    for git_path in entries:
        if git_path == "tasks/.gitkeep":
            continue
        task_key = validate_index_entry(git_path, entries[git_path][0], "blob")
        assert task_key is not None
        path = root / git_path
        if path.is_symlink() or not path.is_file():
            raise Reject("BLOB_NOT_REGULAR", "task-context artifact is not a regular checked-out file")
        mode = os.stat(path, follow_symlinks=False).st_mode
        if mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
            raise Reject("BLOB_NOT_REGULAR", "task-context artifact is executable")
        validate_pack_bytes(path.read_bytes(), expected_task_key=task_key)

    indexed_paths = set(entries)
    for path in tasks.rglob("*"):
        if path.is_dir() and not path.is_symlink():
            continue
        git_path = path.relative_to(root).as_posix()
        if git_path not in indexed_paths:
            raise Reject("FORBIDDEN_PATH", "unindexed or noncanonical task artifact is present")


def main(argv: list[str]) -> int:
    try:
        validate_repository(Path(argv[1] if len(argv) > 1 else "."))
    except Reject as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
