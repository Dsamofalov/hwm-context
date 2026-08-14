#!/usr/bin/env python3
"""Transactional runtime for the hwm-context historical-ledger publisher.

This runtime keeps candidate bytes inert and compensates a scoped branch ref if
PR creation or explicit CI dispatch fails after ref creation.
"""
from __future__ import annotations

import base64
import copy
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
    GitHub,
    REPOSITORY,
    REQUEST_SCHEMA,
    REQUIRED_CHECK,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    TRANSPORT_ISSUE,
    Reject,
    _comment_json,
    _sha,
    canonical_json,
    cleanup,
    error_result,
    fingerprint,
    git_blob_sha,
    preflight,
    validate_public_blob,
    validate_request,
)


def classify_pr_error(exc: RuntimeError) -> Reject:
    text = str(exc).lower()
    if "failed with 403" in text and (
        "not permitted to create or approve pull requests" in text
        or "github actions" in text
        or "resource not accessible by integration" in text
    ):
        return Reject(
            "PR_CREATION_FORBIDDEN",
            "repository Actions workflow permissions block the built-in GITHUB_TOKEN from creating the publication PR",
        )
    return Reject("PR_CREATION_FAILED", "scoped publication PR creation failed")


class TransactionalPublisher:
    def __init__(self, api: GitHub):
        self.api = api

    def _prior(self, request: dict[str, Any], fp: str, current_comment_id: int | None) -> dict[str, Any] | None:
        for comment in self.api.comments():
            obj = _comment_json(comment)
            if not obj or obj.get("request_id") != request["request_id"]:
                continue
            user = comment.get("user") or {}
            if obj.get("schema") == REQUEST_SCHEMA and comment.get("id") != current_comment_id:
                if (
                    user.get("login") == ALLOWED_AUTHOR["login"]
                    and user.get("id") == ALLOWED_AUTHOR["id"]
                    and fingerprint(obj) != fp
                ):
                    raise Reject("REQUEST_ID_REUSE", "request_id was previously used with different normalized payload")
            if obj.get("schema") == RESULT_SCHEMA and user.get("login") == RESULT_AUTHOR["login"]:
                if obj.get("request_fingerprint") != fp:
                    raise Reject("REQUEST_ID_REUSE", "request_id already has a result for different normalized payload")
                replay = copy.deepcopy(obj)
                replay["idempotent_replay"] = True
                return replay
        return None

    def _delete_scoped_ref(self, branch: str) -> None:
        if not branch.startswith(BRANCH_PREFIX):
            return
        try:
            self.api.request("DELETE", f"/git/refs/heads/{urllib.parse.quote(branch, safe='/')}")
        except Exception:
            pass

    def publish(self, event: dict[str, Any]) -> dict[str, Any] | None:
        comment = event.get("comment") or {}
        issue = event.get("issue") or {}
        repo = event.get("repository") or {}
        author = comment.get("user") or {}
        if issue.get("pull_request") or issue.get("number") != TRANSPORT_ISSUE or repo.get("full_name") != REPOSITORY:
            return None
        if author.get("login") != ALLOWED_AUTHOR["login"] or author.get("id") != ALLOWED_AUTHOR["id"]:
            return None
        try:
            raw = json.loads(comment.get("body", ""))
        except json.JSONDecodeError:
            return None
        if isinstance(raw, dict) and raw.get("schema") == RESULT_SCHEMA:
            return None

        fp = fingerprint(raw)
        branch_created = False
        branch = raw.get("publication_branch") if isinstance(raw, dict) else None
        try:
            request = validate_request(raw)
            fp = fingerprint(request)
            branch = request["publication_branch"]
            replay = self._prior(request, fp, comment.get("id"))
            if replay is not None:
                return replay

            observed = (((self.api.request("GET", "/git/ref/heads/main") or {}).get("object") or {}).get("sha"))
            if observed != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main does not equal expected_base")
            base_commit = self.api.request("GET", f"/git/commits/{request['expected_base']}") or {}
            tree_sha = (base_commit.get("tree") or {}).get("sha")
            if not _sha(tree_sha):
                raise Reject("INTERNAL_ERROR", "base commit tree is unavailable")
            tree = self.api.request("GET", f"/git/trees/{tree_sha}?recursive=1") or {}
            by_path = {
                entry.get("path"): entry
                for entry in tree.get("tree", [])
                if isinstance(entry, dict) and isinstance(entry.get("path"), str)
            }

            for change in request["changes"]:
                current = by_path.get(change["path"])
                if change["op"] == "add":
                    if current is not None:
                        raise Reject("PATH_STATE_MISMATCH", "add target already exists at expected_base")
                else:
                    if not current or current.get("type") != "blob" or current.get("mode") not in {"100644", "100755"}:
                        raise Reject("PATH_STATE_MISMATCH", "replace target is absent or not a regular blob")
                    if current.get("sha") != change["expected_blob_sha"]:
                        raise Reject("PATH_STATE_MISMATCH", "replace target does not match expected_blob_sha")
                blob = self.api.request("GET", f"/git/blobs/{change['blob_sha']}") or {}
                if blob.get("sha") != change["blob_sha"] or blob.get("encoding") != "base64":
                    raise Reject("BLOB_NOT_FOUND", "candidate Git blob is unavailable")
                data = base64.b64decode(blob.get("content", ""), validate=False)
                if git_blob_sha(data) != change["blob_sha"]:
                    raise Reject("BLOB_NOT_REGULAR", "candidate object does not verify as the requested Git blob")
                validate_public_blob(data)

            branch_path = urllib.parse.quote(branch, safe="/")
            try:
                self.api.request("GET", f"/git/ref/heads/{branch_path}")
                raise Reject("BRANCH_EXISTS", "scoped publication branch already exists without an exact replay result")
            except RuntimeError as exc:
                if "failed with 404" not in str(exc):
                    raise

            if (((self.api.request("GET", "/git/ref/heads/main") or {}).get("object") or {}).get("sha")) != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main changed before publication mutation")
            new_tree = self.api.request(
                "POST",
                "/git/trees",
                {
                    "base_tree": tree_sha,
                    "tree": [
                        {"path": change["path"], "mode": "100644", "type": "blob", "sha": change["blob_sha"]}
                        for change in request["changes"]
                    ],
                },
            ) or {}
            new_tree_sha = new_tree.get("sha")
            if not _sha(new_tree_sha):
                raise Reject("INTERNAL_ERROR", "candidate tree creation returned no exact SHA")
            new_commit = self.api.request(
                "POST",
                "/git/commits",
                {
                    "message": (
                        f"historical-ledger: {request['request_id']}\n\n"
                        f"HWM-Ledger-Request-Id: {request['request_id']}\n"
                        f"HWM-Ledger-Request-Fingerprint: {fp}"
                    ),
                    "tree": new_tree_sha,
                    "parents": [request["expected_base"]],
                },
            ) or {}
            new_head = new_commit.get("sha")
            if not _sha(new_head):
                raise Reject("INTERNAL_ERROR", "candidate commit creation returned no exact SHA")
            if (((self.api.request("GET", "/git/ref/heads/main") or {}).get("object") or {}).get("sha")) != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main changed before scoped ref creation")
            self.api.request("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": new_head})
            branch_created = True

            try:
                pr = self.api.request(
                    "POST",
                    "/pulls",
                    {
                        "title": f"Historical ledger publication {request['request_id']}",
                        "head": branch,
                        "base": DEFAULT_BRANCH,
                        "body": (
                            "Generated historical-ledger publication. Publisher does not merge this PR. "
                            f"Exact request id: `{request['request_id']}`."
                        ),
                    },
                ) or {}
            except RuntimeError as exc:
                self._delete_scoped_ref(branch)
                branch_created = False
                raise classify_pr_error(exc)
            pr_number = pr.get("number")
            if not isinstance(pr_number, int):
                self._delete_scoped_ref(branch)
                branch_created = False
                raise Reject("PR_CREATION_FAILED", "scoped publication PR creation returned no number")

            try:
                self.api.request(
                    "POST",
                    f"/actions/workflows/{CI_WORKFLOW}/dispatches",
                    {
                        "ref": branch,
                        "inputs": {"request_id": request["request_id"], "expected_head": new_head},
                    },
                )
            except RuntimeError as exc:
                try:
                    self.api.request("PATCH", f"/pulls/{pr_number}", {"state": "closed"})
                finally:
                    self._delete_scoped_ref(branch)
                    branch_created = False
                raise Reject("CI_DISPATCH_FAILED", "explicit bootstrap CI dispatch failed") from exc

            run_id = None
            for _ in range(25):
                runs = self.api.request(
                    "GET",
                    f"/actions/workflows/{CI_WORKFLOW}/runs?event=workflow_dispatch&branch={urllib.parse.quote(branch, safe='')}&per_page=20",
                ) or {}
                for run in runs.get("workflow_runs", []):
                    if run.get("head_sha") == new_head and run.get("event") == "workflow_dispatch" and run.get("path") == CI_PATH:
                        run_id = run.get("id")
                        break
                if isinstance(run_id, int):
                    break
                time.sleep(1)
            if not isinstance(run_id, int):
                try:
                    self.api.request("PATCH", f"/pulls/{pr_number}", {"state": "closed"})
                finally:
                    self._delete_scoped_ref(branch)
                    branch_created = False
                raise Reject("CI_DISPATCH_FAILED", "explicit bootstrap CI run could not be associated with exact candidate head")

            return {
                "schema": RESULT_SCHEMA,
                "request_id": request["request_id"],
                "status": "success",
                "repository": REPOSITORY,
                "transport_issue": TRANSPORT_ISSUE,
                "expected_base": request["expected_base"],
                "publication_branch": branch,
                "request_fingerprint": fp,
                "idempotent_replay": False,
                "commit_sha": new_head,
                "pr_number": pr_number,
                "ci_dispatch": {
                    "workflow": CI_WORKFLOW,
                    "run_id": run_id,
                    "head_sha": new_head,
                    "required_check": REQUIRED_CHECK,
                },
                "error": None,
            }
        except Reject as exc:
            if branch_created and isinstance(branch, str):
                self._delete_scoped_ref(branch)
            return error_result(raw, exc.code, exc.message, fp=fp)
        except Exception:
            if branch_created and isinstance(branch, str):
                self._delete_scoped_ref(branch)
            return error_result(raw, "INTERNAL_ERROR", "publisher encountered a sanitized internal failure", fp=fp)


def _outputs(values: dict[str, str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        for key, value in values.items():
            print(f"{key}={value}")
        return
    with open(path, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"preflight", "publish", "cleanup"}:
        print("usage: historical_ledger_publisher_v2.py {preflight|publish|cleanup} EVENT_JSON", file=sys.stderr)
        return 2
    with open(argv[2], "r", encoding="utf-8") as handle:
        event = json.load(handle)
    if argv[1] == "preflight":
        _outputs(preflight(event))
        return 0
    token = os.environ.pop("HWM_CONTEXT_PUBLISHER_TOKEN", None)
    if not token:
        print("publisher job token unavailable", file=sys.stderr)
        return 2
    api = GitHub(token)
    if argv[1] == "cleanup":
        cleanup(event, api)
        return 0
    result = TransactionalPublisher(api).publish(event)
    if result is not None:
        api.request("POST", f"/issues/{TRANSPORT_ISSUE}/comments", {"body": canonical_json(result)})
        print(f"publish_status={result['status']} request_id={result['request_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
