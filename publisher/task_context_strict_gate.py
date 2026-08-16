#!/usr/bin/env python3
"""Protected-main strict status gate for generated task-context PRs.

This runtime has read authority plus statuses:write only. It independently
revalidates request/result/PR/base/head/tree/blob/bytes/CI before publishing the
required bootstrap commit status.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

from publisher.task_context_contract import (
    ALLOWED_AUTHOR,
    CI_PATH,
    DEFAULT_BRANCH,
    REPOSITORY,
    REQUIRED_CHECK,
    REQUIRED_INTEGRATION_ID,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    TRANSPORT_ISSUE,
    Reject,
    canonical_json,
    fingerprint,
    is_hex256,
    is_sha,
    sha256,
    validate_pack_bytes,
    validate_request,
    validate_result,
)
from publisher.task_context_publisher import GitHub, blob_bytes, comment_json

STATUS_DESCRIPTION_PREFIX = "Trusted task-context gate "


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject("STRICT_GATE_REJECTED", message)


def request_from_event(event: dict[str, Any]) -> tuple[dict[str, Any], str]:
    repository = event.get("repository") or {}
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    author = comment.get("user") or {}
    require(repository.get("full_name") == REPOSITORY, "event repository mismatch")
    require(issue.get("number") == TRANSPORT_ISSUE and not issue.get("pull_request"), "transport Issue mismatch")
    require(
        author.get("login") == ALLOWED_AUTHOR["login"] and author.get("id") == ALLOWED_AUTHOR["id"],
        "transport author mismatch",
    )
    try:
        raw = json.loads(comment.get("body", ""))
    except json.JSONDecodeError as exc:
        raise Reject("STRICT_GATE_REJECTED", "transport request is not JSON") from exc
    request = validate_request(raw)
    return request, fingerprint(request)


def matching_result(api: GitHub, request: dict[str, Any], request_fingerprint: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for comment in api.comments():
        user = comment.get("user") or {}
        obj = comment_json(comment)
        if (
            user.get("login") != RESULT_AUTHOR["login"]
            or user.get("id") != RESULT_AUTHOR["id"]
            or not obj
            or obj.get("schema") != RESULT_SCHEMA
            or obj.get("request_id") != request["request_id"]
        ):
            continue
        try:
            validate_result(obj)
        except Reject:
            continue
        if obj.get("request_fingerprint") == request_fingerprint and obj.get("status") == "success" and obj.get("error") is None:
            matches.append(obj)
    require(bool(matches), "matching successful publication result is unavailable")
    first = matches[0]
    for other in matches[1:]:
        for key in ("expected_base", "publication_branch", "task", "artifact", "candidate", "pr", "ci_dispatch", "required_status"):
            require(other.get(key) == first.get(key), "matching successful replay results disagree")
    return first


def main_head(api: GitHub) -> str | None:
    ref = api.request("GET", "/git/ref/heads/main") or {}
    return ((ref.get("object") or {}).get("sha"))


def branch_head(api: GitHub, branch: str) -> str | None:
    import urllib.parse

    ref = api.request("GET", f"/git/ref/heads/{urllib.parse.quote(branch, safe='/')}") or {}
    return ((ref.get("object") or {}).get("sha"))


def recursive_tree(api: GitHub, tree_sha: str) -> dict[str, dict[str, Any]]:
    tree = api.request("GET", f"/git/trees/{tree_sha}?recursive=1") or {}
    require(tree.get("truncated") is not True, "tree response was truncated")
    return {
        entry.get("path"): entry
        for entry in tree.get("tree", [])
        if isinstance(entry, dict) and isinstance(entry.get("path"), str)
    }


def provenance_trailers(message: Any) -> tuple[str, str]:
    lines = str(message).splitlines()
    request_ids = [line.removeprefix("HWM-Task-Context-Request-Id: ") for line in lines if line.startswith("HWM-Task-Context-Request-Id: ")]
    fingerprints = [
        line.removeprefix("HWM-Task-Context-Request-Fingerprint: ")
        for line in lines
        if line.startswith("HWM-Task-Context-Request-Fingerprint: ")
    ]
    require(len(request_ids) == 1 and len(fingerprints) == 1 and is_hex256(fingerprints[0]), "candidate provenance trailers are not exact")
    return request_ids[0], fingerprints[0]


def wait_exact_candidate_ci(api: GitHub, result: dict[str, Any]) -> int:
    run_id = result["ci_dispatch"]["run_id"]
    expected_head = result["candidate"]["commit_sha"]
    expected_branch = result["publication_branch"]
    for _ in range(45):
        run = api.request("GET", f"/actions/runs/{run_id}") or {}
        require(
            run.get("head_sha") == expected_head
            and run.get("head_branch") == expected_branch
            and run.get("event") == "workflow_dispatch"
            and run.get("path") == CI_PATH,
            "candidate bootstrap run identity mismatch",
        )
        if run.get("status") == "completed":
            require(run.get("conclusion") == "success", "exact candidate bootstrap did not succeed")
            return run_id
        time.sleep(2)
    raise Reject("STRICT_GATE_REJECTED", "exact candidate bootstrap did not complete")


def existing_exact_status(api: GitHub, head_sha: str, description: str) -> dict[str, Any] | None:
    statuses = api.request("GET", f"/commits/{head_sha}/statuses?per_page=100") or []
    exact = [
        status
        for status in statuses
        if isinstance(status, dict)
        and status.get("context") == REQUIRED_CHECK
        and status.get("description") == description
        and (status.get("creator") or {}).get("login") == RESULT_AUTHOR["login"]
        and (status.get("creator") or {}).get("id") == RESULT_AUTHOR["id"]
    ]
    require(len(exact) <= 1, "multiple exact strict statuses exist")
    return exact[0] if exact else None


def validate_snapshot(
    *,
    expected_base: str,
    first_main: str | None,
    final_main: str | None,
    first_branch_head: str | None,
    final_branch_head: str | None,
    first_pr: dict[str, Any],
    final_pr: dict[str, Any],
    expected_head: str,
    expected_merge: str,
) -> None:
    first_base = first_pr.get("base") or {}
    final_base = final_pr.get("base") or {}
    first_head = first_pr.get("head") or {}
    final_head = final_pr.get("head") or {}
    require(
        first_main == final_main == expected_base
        and first_base.get("sha") == final_base.get("sha") == expected_base,
        "protected base drifted during strict validation",
    )
    require(
        first_branch_head == final_branch_head == expected_head
        and first_head.get("sha") == final_head.get("sha") == expected_head,
        "candidate head drifted during strict validation",
    )
    require(first_pr.get("merge_commit_sha") == final_pr.get("merge_commit_sha") == expected_merge, "synthetic merge changed during strict validation")
    require(first_pr.get("state") == final_pr.get("state") == "open", "generated PR state changed during strict validation")


def publish_strict_status(event: dict[str, Any], api: GitHub) -> dict[str, Any]:
    request, request_fingerprint = request_from_event(event)
    result = matching_result(api, request, request_fingerprint)
    candidate = result["candidate"]
    result_pr = result["pr"]
    artifact = request["artifact"]

    require(result["expected_base"] == request["expected_base"], "result expected_base differs from request")
    require(result["publication_branch"] == request["publication_branch"], "result publication branch differs from request")
    require(result["task"] == request["task"] and result["artifact"] == artifact, "result task/artifact differs from request")
    require(candidate["parent_sha"] == request["expected_base"] and candidate["parent_count"] == 1, "result candidate parent differs from request")
    require(result_pr["head_sha"] == candidate["commit_sha"] and result_pr["head_ref"] == request["publication_branch"], "result PR head differs from candidate")
    require(result["ci_dispatch"]["head_sha"] == candidate["commit_sha"], "result dispatch head differs from candidate")
    require(result["required_status"]["integration_id"] == REQUIRED_INTEGRATION_ID, "result required-status integration provenance mismatch")

    pr = api.request("GET", f"/pulls/{result_pr['number']}") or {}
    base = pr.get("base") or {}
    head = pr.get("head") or {}
    head_repository = head.get("repo") or {}
    pr_author = pr.get("user") or {}
    require(pr.get("state") == "open", "generated PR is not open")
    require(pr_author.get("login") == RESULT_AUTHOR["login"] and pr_author.get("id") == RESULT_AUTHOR["id"], "generated PR author is not Actions bot")
    require(base.get("ref") == DEFAULT_BRANCH and base.get("sha") == request["expected_base"], "generated PR base mismatch")
    require(
        head.get("ref") == request["publication_branch"]
        and head.get("sha") == candidate["commit_sha"]
        and head_repository.get("full_name") == REPOSITORY,
        "generated PR head mismatch",
    )

    first_main = main_head(api)
    first_branch = branch_head(api, request["publication_branch"])
    require(first_main == request["expected_base"], "protected main already drifted")
    require(first_branch == candidate["commit_sha"], "publication branch already drifted")

    head_commit = api.request("GET", f"/git/commits/{candidate['commit_sha']}") or {}
    head_tree = (head_commit.get("tree") or {}).get("sha")
    parents = [parent.get("sha") for parent in head_commit.get("parents", [])]
    require(parents == [request["expected_base"]], "candidate does not have exact single protected-base parent")
    require(head_tree == candidate["tree_sha"] and is_sha(head_tree), "candidate result tree mismatch")
    trailer_request, trailer_fingerprint = provenance_trailers(head_commit.get("message"))
    require(trailer_request == request["request_id"] and trailer_fingerprint == request_fingerprint, "candidate request provenance trailers mismatch")

    files = api.request("GET", f"/pulls/{result_pr['number']}/files?per_page=100") or []
    require(isinstance(files, list) and len(files) == 1, "generated PR does not contain exactly one file")
    require(files[0].get("filename") == artifact["path"] and files[0].get("sha") == artifact["blob_sha"], "generated PR path/blob mismatch")
    require(files[0].get("status") in {"added", "modified"}, "generated PR operation is not add/replace")

    base_commit = api.request("GET", f"/git/commits/{request['expected_base']}") or {}
    base_tree = (base_commit.get("tree") or {}).get("sha")
    require(is_sha(base_tree), "protected-base tree unavailable")
    base_entries = recursive_tree(api, base_tree)
    head_entries = recursive_tree(api, head_tree)
    base_entry = base_entries.get(artifact["path"])
    head_entry = head_entries.get(artifact["path"])
    require(
        head_entry
        and head_entry.get("type") == "blob"
        and head_entry.get("mode") == "100644"
        and head_entry.get("sha") == artifact["blob_sha"],
        "candidate tree target mismatch",
    )
    if artifact["op"] == "add":
        require(base_entry is None, "add target already existed at protected base")
    else:
        require(
            base_entry
            and base_entry.get("type") == "blob"
            and base_entry.get("mode") == "100644"
            and base_entry.get("sha") == artifact["expected_blob_sha"],
            "replace base blob mismatch",
        )

    data = blob_bytes(api, artifact["blob_sha"])
    require(sha256(data) == artifact["content_sha256"], "candidate blob SHA-256 mismatch")
    validate_pack_bytes(data, request)

    merge_sha = pr.get("merge_commit_sha")
    require(is_sha(merge_sha), "synthetic merge commit unavailable")
    merge_commit = api.request("GET", f"/git/commits/{merge_sha}") or {}
    merge_tree = (merge_commit.get("tree") or {}).get("sha")
    merge_parents = [parent.get("sha") for parent in merge_commit.get("parents", [])]
    require(merge_parents == [request["expected_base"], candidate["commit_sha"]], "synthetic merge parents mismatch")
    require(merge_tree == head_tree, "synthetic merge tree differs from exact candidate tree")

    run_id = wait_exact_candidate_ci(api, result)

    final_main = main_head(api)
    final_branch = branch_head(api, request["publication_branch"])
    final_pr = api.request("GET", f"/pulls/{result_pr['number']}") or {}
    validate_snapshot(
        expected_base=request["expected_base"],
        first_main=first_main,
        final_main=final_main,
        first_branch_head=first_branch,
        final_branch_head=final_branch,
        first_pr=pr,
        final_pr=final_pr,
        expected_head=candidate["commit_sha"],
        expected_merge=merge_sha,
    )

    description = STATUS_DESCRIPTION_PREFIX + request_fingerprint
    existing = existing_exact_status(api, candidate["commit_sha"], description)
    if existing is not None:
        require(existing.get("state") == "success", "existing exact strict status is not successful")
        return {
            "idempotent_replay": True,
            "status_id": existing.get("id"),
            "request_id": request["request_id"],
            "request_fingerprint": request_fingerprint,
            "pr_number": result_pr["number"],
            "base_sha": request["expected_base"],
            "candidate_head_sha": candidate["commit_sha"],
            "candidate_tree_sha": head_tree,
            "candidate_bootstrap_run_id": run_id,
            "path": artifact["path"],
        }

    status = api.request(
        "POST",
        f"/statuses/{candidate['commit_sha']}",
        {
            "state": "success",
            "context": REQUIRED_CHECK,
            "description": description,
            "target_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        },
    ) or {}
    require(
        status.get("state") == "success"
        and status.get("context") == REQUIRED_CHECK
        and status.get("description") == description,
        "created strict status does not match requested status",
    )
    creator = status.get("creator") or {}
    require(
        creator.get("login") == RESULT_AUTHOR["login"] and creator.get("id") == RESULT_AUTHOR["id"],
        "strict status source is not the Actions installation",
    )
    require(main_head(api) == request["expected_base"] and branch_head(api, request["publication_branch"]) == candidate["commit_sha"], "base/head drifted while publishing strict status")

    return {
        "idempotent_replay": False,
        "status_id": status.get("id"),
        "request_id": request["request_id"],
        "request_fingerprint": request_fingerprint,
        "pr_number": result_pr["number"],
        "base_sha": request["expected_base"],
        "candidate_head_sha": candidate["commit_sha"],
        "candidate_tree_sha": head_tree,
        "candidate_bootstrap_run_id": run_id,
        "path": artifact["path"],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: task_context_strict_gate.py EVENT_JSON", file=sys.stderr)
        return 2
    token = os.environ.pop("HWM_TASK_CONTEXT_STRICT_GATE_TOKEN", None)
    if not token:
        print("strict gate token unavailable", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as handle:
        event = json.load(handle)
    try:
        evidence = publish_strict_status(event, GitHub(token))
    except Reject as exc:
        print(f"strict_status={exc.code}: {exc.message}", file=sys.stderr)
        return 1
    print(canonical_json(evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
