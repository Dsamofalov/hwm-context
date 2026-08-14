#!/usr/bin/env python3
"""Trusted pull-request-context gate for generated historical-ledger PRs.

The gate runs only from protected-base workflow code. It never checks out or
executes candidate content. It revalidates the exact publication request,
candidate Git objects, PR identity, and GitHub synthetic merge object, and it
waits for the mandatory exact-candidate workflow_dispatch bootstrap to succeed
before allowing the PR-context ``bootstrap`` job to become green.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import time
import urllib.parse
from typing import Any

from publisher.historical_ledger_publisher import (
    ALLOWED_AUTHOR,
    ALLOWED_PATHS,
    BRANCH_PREFIX,
    CI_PATH,
    CI_WORKFLOW,
    DEFAULT_BRANCH,
    REPOSITORY,
    RESULT_AUTHOR,
    GitHub,
    Reject,
    _sha,
    canonical_json,
    fingerprint,
    git_blob_sha,
    validate_public_blob,
    validate_request,
)


PULL_REQUEST_TARGET_ACTIONS = {"opened", "reopened", "synchronize"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject("STRICT_GATE_REJECTED", message)


def validate_strict_snapshot(
    *,
    event_pr_number: Any,
    first_pr_number: Any,
    final_pr_number: Any,
    expected_base: Any,
    event_base: Any,
    first_base: Any,
    final_base: Any,
    first_main: Any,
    final_main: Any,
    event_head: Any,
    first_head: Any,
    final_head: Any,
    first_merge: Any,
    final_merge: Any,
    changed_paths: list[str],
    head_parents: list[str],
    merge_parents: list[str],
    head_tree: Any,
    merge_tree: Any,
) -> None:
    """Fail closed on PR/base/head/merge/path drift and merge-object mismatch."""
    _require(
        isinstance(event_pr_number, int)
        and event_pr_number == first_pr_number == final_pr_number,
        "wrong PR identity",
    )
    _require(_sha(expected_base), "request expected_base is invalid")
    _require(
        event_base == first_base == final_base == first_main == final_main == expected_base,
        "stale or changed protected base",
    )
    _require(
        _sha(event_head) and event_head == first_head == final_head,
        "stale or changed candidate head",
    )
    _require(
        _sha(first_merge) and first_merge == final_merge,
        "synthetic merge SHA changed during validation",
    )
    _require(
        len(changed_paths) == len(ALLOWED_PATHS)
        and set(changed_paths) == set(ALLOWED_PATHS),
        "PR paths are not exactly the two canonical generated outputs",
    )
    _require(head_parents == [expected_base], "candidate parent is not exact protected base")
    _require(
        merge_parents == [expected_base, event_head],
        "synthetic merge parents do not match exact base and candidate head",
    )
    _require(_sha(head_tree) and merge_tree == head_tree, "synthetic merge tree does not equal candidate tree")


def _request_identity(message: Any) -> tuple[str, str]:
    _require(isinstance(message, str), "candidate commit message is unavailable")
    request_ids = [
        line.removeprefix("HWM-Ledger-Request-Id: ")
        for line in message.splitlines()
        if line.startswith("HWM-Ledger-Request-Id: ")
    ]
    fingerprints = [
        line.removeprefix("HWM-Ledger-Request-Fingerprint: ")
        for line in message.splitlines()
        if line.startswith("HWM-Ledger-Request-Fingerprint: ")
    ]
    _require(len(request_ids) == 1 and len(fingerprints) == 1, "candidate provenance trailers are not exact")
    request_id = request_ids[0]
    fp = fingerprints[0]
    _require(len(fp) == 64 and all(ch in "0123456789abcdef" for ch in fp), "candidate request fingerprint is invalid")
    return request_id, fp


def _matching_request(api: GitHub, request_id: str, fp: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for comment in api.comments():
        user = comment.get("user") or {}
        if user.get("login") != ALLOWED_AUTHOR["login"] or user.get("id") != ALLOWED_AUTHOR["id"]:
            continue
        body = comment.get("body")
        if not isinstance(body, str):
            continue
        try:
            raw = json.loads(body)
        except json.JSONDecodeError:
            continue
        if not isinstance(raw, dict) or raw.get("request_id") != request_id:
            continue
        try:
            request = validate_request(raw)
        except Reject:
            continue
        if fingerprint(request) == fp:
            matches.append(request)
    _require(len(matches) == 1, "canonical publication request was not uniquely resolved")
    return matches[0]


def _tree_by_path(api: GitHub, tree_sha: str) -> dict[str, dict[str, Any]]:
    tree = api.request("GET", f"/git/trees/{tree_sha}?recursive=1") or {}
    return {
        entry.get("path"): entry
        for entry in tree.get("tree", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }


def _ref_main(api: GitHub) -> str | None:
    ref = api.request("GET", f"/git/ref/heads/{DEFAULT_BRANCH}") or {}
    return ((ref.get("object") or {}).get("sha"))


def _pr_identity(pr: dict[str, Any]) -> tuple[Any, Any, Any, Any, Any]:
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    return pr.get("number"), base.get("ref"), base.get("sha"), head.get("ref"), head.get("sha")


def _wait_for_candidate_bootstrap(api: GitHub, branch: str, head_sha: str) -> int:
    encoded = urllib.parse.quote(branch, safe="")
    for _ in range(45):
        runs = api.request(
            "GET",
            f"/actions/workflows/{CI_WORKFLOW}/runs?event=workflow_dispatch&branch={encoded}&per_page=20",
        ) or {}
        exact = [
            run
            for run in runs.get("workflow_runs", [])
            if run.get("head_sha") == head_sha
            and run.get("head_branch") == branch
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == CI_PATH
        ]
        for run in exact:
            if run.get("status") == "completed" and run.get("conclusion") == "success":
                run_id = run.get("id")
                _require(isinstance(run_id, int), "candidate bootstrap run id is invalid")
                return run_id
        if any(run.get("status") == "completed" and run.get("conclusion") not in {None, "success"} for run in exact):
            raise Reject("STRICT_GATE_REJECTED", "exact candidate bootstrap did not succeed")
        time.sleep(2)
    raise Reject("STRICT_GATE_REJECTED", "exact candidate bootstrap did not become successful")


def validate_generated_pr(event: dict[str, Any], api: GitHub) -> dict[str, Any]:
    repo = event.get("repository") or {}
    event_pr = event.get("pull_request") or {}
    _require(repo.get("full_name") == REPOSITORY, "event repository mismatch")
    _require(event.get("action") in PULL_REQUEST_TARGET_ACTIONS, "unsupported pull_request_target action")
    event_number = event.get("number")
    _require(isinstance(event_number, int), "event PR number is invalid")

    event_user = event_pr.get("user") or {}
    event_base_obj = event_pr.get("base") or {}
    event_head_obj = event_pr.get("head") or {}
    event_head_repo = event_head_obj.get("repo") or {}
    _require(
        event_user.get("login") == RESULT_AUTHOR["login"] and event_user.get("id") == RESULT_AUTHOR["id"],
        "generated PR author is not the trusted GitHub Actions bot",
    )
    _require(event_base_obj.get("ref") == DEFAULT_BRANCH, "generated PR base ref is not protected main")
    _require(event_head_repo.get("full_name") == REPOSITORY, "generated PR head repository mismatch")
    event_branch = event_head_obj.get("ref")
    event_head = event_head_obj.get("sha")
    event_base = event_base_obj.get("sha")
    _require(isinstance(event_branch, str) and event_branch.startswith(BRANCH_PREFIX), "generated PR head branch is outside scoped publisher namespace")
    _require(_sha(event_head) and _sha(event_base), "generated PR event SHAs are invalid")

    first_main = _ref_main(api)
    first_pr = api.request("GET", f"/pulls/{event_number}") or {}
    first_number, first_base_ref, first_base, first_branch, first_head = _pr_identity(first_pr)
    _require(first_pr.get("state") == "open", "generated PR is not open")
    _require(first_base_ref == DEFAULT_BRANCH and first_branch == event_branch, "generated PR refs changed")
    first_user = first_pr.get("user") or {}
    _require(
        first_user.get("login") == RESULT_AUTHOR["login"] and first_user.get("id") == RESULT_AUTHOR["id"],
        "current PR author is not the trusted GitHub Actions bot",
    )

    head_commit = api.request("GET", f"/git/commits/{first_head}") or {}
    head_tree = (head_commit.get("tree") or {}).get("sha")
    head_parents = [parent.get("sha") for parent in head_commit.get("parents", [])]
    request_id, fp = _request_identity(head_commit.get("message"))
    request = _matching_request(api, request_id, fp)
    _require(request.get("expected_base") == first_base, "request expected_base does not match PR base")
    _require(request.get("publication_branch") == first_branch, "request publication branch does not match PR head")

    files = api.request("GET", f"/pulls/{event_number}/files?per_page=100") or []
    _require(isinstance(files, list), "PR changed-files response is invalid")
    changed_paths = [item.get("filename") for item in files if isinstance(item, dict)]
    requested = {change["path"]: change for change in request["changes"]}
    _require(len(files) == len(ALLOWED_PATHS), "generated PR has extra changed paths")
    for item in files:
        _require(isinstance(item, dict), "generated PR file entry is invalid")
        path = item.get("filename")
        _require(path in requested, "generated PR contains a noncanonical path")
        _require(item.get("sha") == requested[path]["blob_sha"], "PR file blob does not match requested candidate blob")

    base_commit = api.request("GET", f"/git/commits/{first_base}") or {}
    base_tree = (base_commit.get("tree") or {}).get("sha")
    _require(_sha(base_tree) and _sha(head_tree), "base or candidate tree SHA is invalid")
    base_paths = _tree_by_path(api, base_tree)
    head_paths = _tree_by_path(api, head_tree)
    for change in request["changes"]:
        path = change["path"]
        base_entry = base_paths.get(path)
        head_entry = head_paths.get(path)
        _require(
            head_entry is not None
            and head_entry.get("type") == "blob"
            and head_entry.get("mode") == "100644"
            and head_entry.get("sha") == change["blob_sha"],
            "candidate tree does not contain the exact requested regular blob",
        )
        if change["op"] == "add":
            _require(base_entry is None, "request add path already exists at base")
        else:
            _require(
                base_entry is not None
                and base_entry.get("type") == "blob"
                and base_entry.get("sha") == change["expected_blob_sha"],
                "request replace base blob mismatch",
            )
        blob = api.request("GET", f"/git/blobs/{change['blob_sha']}") or {}
        _require(blob.get("sha") == change["blob_sha"] and blob.get("encoding") == "base64", "candidate blob is unavailable")
        data = base64.b64decode(blob.get("content", ""), validate=False)
        _require(git_blob_sha(data) == change["blob_sha"], "candidate blob Git identity mismatch")
        validate_public_blob(data)

    first_merge = first_pr.get("merge_commit_sha")
    _require(_sha(first_merge), "current synthetic merge SHA is unavailable")
    merge_commit = api.request("GET", f"/git/commits/{first_merge}") or {}
    merge_tree = (merge_commit.get("tree") or {}).get("sha")
    merge_parents = [parent.get("sha") for parent in merge_commit.get("parents", [])]

    candidate_run_id = _wait_for_candidate_bootstrap(api, first_branch, first_head)

    final_main = _ref_main(api)
    final_pr = api.request("GET", f"/pulls/{event_number}") or {}
    final_number, final_base_ref, final_base, final_branch, final_head = _pr_identity(final_pr)
    final_merge = final_pr.get("merge_commit_sha")
    _require(final_pr.get("state") == "open", "generated PR closed during validation")
    _require(final_base_ref == DEFAULT_BRANCH and final_branch == first_branch, "generated PR refs drifted during validation")

    validate_strict_snapshot(
        event_pr_number=event_number,
        first_pr_number=first_number,
        final_pr_number=final_number,
        expected_base=request["expected_base"],
        event_base=event_base,
        first_base=first_base,
        final_base=final_base,
        first_main=first_main,
        final_main=final_main,
        event_head=event_head,
        first_head=first_head,
        final_head=final_head,
        first_merge=first_merge,
        final_merge=final_merge,
        changed_paths=changed_paths,
        head_parents=head_parents,
        merge_parents=merge_parents,
        head_tree=head_tree,
        merge_tree=merge_tree,
    )

    return {
        "request_id": request_id,
        "request_fingerprint": fp,
        "pr_number": event_number,
        "base_sha": first_base,
        "candidate_head_sha": first_head,
        "synthetic_merge_sha": first_merge,
        "candidate_bootstrap_run_id": candidate_run_id,
        "paths": sorted(changed_paths),
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: strict_generated_pr_gate.py EVENT_JSON", file=sys.stderr)
        return 2
    token = os.environ.pop("HWM_CONTEXT_GATE_TOKEN", None)
    if not token:
        print("strict gate token unavailable", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as handle:
        event = json.load(handle)
    try:
        evidence = validate_generated_pr(event, GitHub(token))
    except Reject as exc:
        print(f"strict_gate={exc.code}: {exc.message}", file=sys.stderr)
        return 1
    print(canonical_json(evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
