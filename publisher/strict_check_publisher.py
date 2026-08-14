#!/usr/bin/env python3
"""Publish the strict required commit status after trusted generated-PR validation.

This runtime executes from protected ``main`` in the user-originated historical
publisher workflow. Its token has read access plus ``statuses: write`` only. It
never checks out or executes candidate content and has no PR mutation or
contents-write authority.
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any

from publisher.historical_ledger_publisher import (
    ALLOWED_AUTHOR,
    REPOSITORY,
    REQUEST_SCHEMA,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    TRANSPORT_ISSUE,
    GitHub,
    Reject,
    _comment_json,
    fingerprint,
    validate_request,
)
from publisher.strict_generated_pr_gate import validate_generated_pr


CHECK_NAME = "bootstrap"
STATUS_DESCRIPTION_PREFIX = "Trusted generated-ledger gate "


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise Reject("STRICT_STATUS_REJECTED", message)


def _request_from_event(event: dict[str, Any]) -> tuple[dict[str, Any], str]:
    repo = event.get("repository") or {}
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    author = comment.get("user") or {}
    _require(repo.get("full_name") == REPOSITORY, "event repository mismatch")
    _require(issue.get("number") == TRANSPORT_ISSUE and not issue.get("pull_request"), "event transport issue mismatch")
    _require(
        author.get("login") == ALLOWED_AUTHOR["login"] and author.get("id") == ALLOWED_AUTHOR["id"],
        "transport author mismatch",
    )
    try:
        raw = json.loads(comment.get("body", ""))
    except json.JSONDecodeError as exc:
        raise Reject("STRICT_STATUS_REJECTED", "transport request is not JSON") from exc
    request = validate_request(raw)
    _require(request.get("schema") == REQUEST_SCHEMA, "transport request schema mismatch")
    return request, fingerprint(request)


def _matching_success_result(api: GitHub, request: dict[str, Any], fp: str) -> dict[str, Any]:
    matches: list[dict[str, Any]] = []
    for comment in api.comments():
        user = comment.get("user") or {}
        if user.get("login") != RESULT_AUTHOR["login"] or user.get("id") != RESULT_AUTHOR["id"]:
            continue
        obj = _comment_json(comment)
        if not obj or obj.get("schema") != RESULT_SCHEMA:
            continue
        if obj.get("request_id") != request["request_id"] or obj.get("request_fingerprint") != fp:
            continue
        if obj.get("status") == "success" and obj.get("error") is None:
            matches.append(obj)
    _require(len(matches) >= 1, "matching successful publication result is unavailable")
    canonical = matches[-1]
    for item in matches:
        _require(
            item.get("commit_sha") == canonical.get("commit_sha")
            and item.get("pr_number") == canonical.get("pr_number")
            and item.get("expected_base") == canonical.get("expected_base")
            and item.get("publication_branch") == canonical.get("publication_branch"),
            "successful replay results disagree on immutable publication identity",
        )
    return canonical


def _synthetic_pr_event(pr: dict[str, Any]) -> dict[str, Any]:
    number = pr.get("number")
    _require(isinstance(number, int), "publication PR number is invalid")
    return {
        "action": "synchronize",
        "number": number,
        "repository": {"full_name": REPOSITORY},
        "pull_request": pr,
    }


def _status_description(fp: str) -> str:
    return f"{STATUS_DESCRIPTION_PREFIX}{fp}"


def _find_existing_exact_status(api: GitHub, head_sha: str, description: str) -> dict[str, Any] | None:
    statuses = api.request("GET", f"/commits/{head_sha}/statuses?per_page=100") or []
    exact = [
        status
        for status in statuses
        if isinstance(status, dict)
        and status.get("context") == CHECK_NAME
        and status.get("description") == description
        and ((status.get("creator") or {}).get("login") == RESULT_AUTHOR["login"])
        and ((status.get("creator") or {}).get("id") == RESULT_AUTHOR["id"])
    ]
    _require(len(exact) <= 1, "multiple strict statuses share one immutable validation identity")
    return exact[0] if exact else None


def publish_strict_status(event: dict[str, Any], api: GitHub) -> dict[str, Any]:
    request, fp = _request_from_event(event)
    result = _matching_success_result(api, request, fp)
    pr_number = result.get("pr_number")
    head_sha = result.get("commit_sha")
    _require(isinstance(pr_number, int), "publication result PR number is invalid")
    _require(isinstance(head_sha, str), "publication result candidate head is invalid")
    _require(result.get("expected_base") == request["expected_base"], "publication result base mismatch")
    _require(result.get("publication_branch") == request["publication_branch"], "publication result branch mismatch")
    dispatch = result.get("ci_dispatch") or {}
    _require(dispatch.get("head_sha") == head_sha, "publication result candidate dispatch head mismatch")
    _require(dispatch.get("required_check") == CHECK_NAME, "publication result required check mismatch")
    _require(isinstance(dispatch.get("run_id"), int), "publication result candidate dispatch run is unavailable")

    pr = api.request("GET", f"/pulls/{pr_number}") or {}
    evidence = validate_generated_pr(_synthetic_pr_event(pr), api)
    _require(evidence.get("request_id") == request["request_id"], "validated request id mismatch")
    _require(evidence.get("request_fingerprint") == fp, "validated request fingerprint mismatch")
    _require(evidence.get("pr_number") == pr_number, "validated PR number mismatch")
    _require(evidence.get("base_sha") == request["expected_base"], "validated base mismatch")
    _require(evidence.get("candidate_head_sha") == head_sha, "validated candidate head mismatch")
    _require(
        evidence.get("candidate_bootstrap_run_id") == dispatch.get("run_id"),
        "validated candidate bootstrap run differs from publication result",
    )

    description = _status_description(fp)
    existing = _find_existing_exact_status(api, head_sha, description)
    if existing is not None:
        _require(existing.get("state") == "success", "existing strict required status is not successful")
        return {
            "idempotent_replay": True,
            "status_id": existing.get("id"),
            **evidence,
        }

    run_id = dispatch["run_id"]
    status = api.request(
        "POST",
        f"/statuses/{head_sha}",
        {
            "state": "success",
            "context": CHECK_NAME,
            "description": description,
            "target_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        },
    ) or {}
    _require(status.get("context") == CHECK_NAME, "created strict status context mismatch")
    _require(status.get("state") == "success", "created strict status is not successful")
    _require(status.get("description") == description, "created strict status validation identity mismatch")
    creator = status.get("creator") or {}
    _require(
        creator.get("login") == RESULT_AUTHOR["login"] and creator.get("id") == RESULT_AUTHOR["id"],
        "created strict status source is not the repository GitHub Actions installation",
    )
    return {
        "idempotent_replay": False,
        "status_id": status.get("id"),
        **evidence,
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: strict_check_publisher.py EVENT_JSON", file=sys.stderr)
        return 2
    token = os.environ.pop("HWM_CONTEXT_STRICT_GATE_TOKEN", None)
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
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
