#!/usr/bin/env python3
"""Transactional trusted publisher for canonical I09 task-context packs.

Candidate bytes are inert Git blob data. This runtime never checks candidate
content out, imports it, evaluates it, executes it, writes protected main,
approves a PR, or merges a PR.
"""
from __future__ import annotations

import base64
import copy
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from publisher.task_context_contract import (
    ALLOWED_AUTHOR,
    BRANCH_PREFIX,
    CI_PATH,
    CI_WORKFLOW,
    DEFAULT_BRANCH,
    REPOSITORY,
    REQUEST_SCHEMA,
    REQUIRED_CHECK,
    REQUIRED_INTEGRATION_ID,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    TRANSPORT_ISSUE,
    Reject,
    canonical_json,
    error_result,
    fingerprint,
    git_blob_sha,
    is_sha,
    sha256,
    validate_pack_bytes,
    validate_request,
    validate_result,
)


class GitHub:
    """Narrow repository-local GitHub REST adapter."""

    def __init__(self, token: str):
        if not token:
            raise ValueError("publisher token required")
        self.token = token
        self.base = f"https://api.github.com/repos/{REPOSITORY}"

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        data = None if payload is None else canonical_json(payload).encode("utf-8")
        request = urllib.request.Request(self.base + path, data=data, method=method)
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        request.add_header("Authorization", f"Bearer {self.token}")
        if data is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
                return None if not raw else json.loads(raw.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:400]
            raise RuntimeError(f"GitHub API {method} {path} failed with {exc.code}: {body}") from exc

    def comments(self) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 11):
            batch = self.request("GET", f"/issues/{TRANSPORT_ISSUE}/comments?per_page=100&page={page}") or []
            if not isinstance(batch, list):
                raise RuntimeError("transport comment listing malformed")
            comments.extend(batch)
            if len(batch) < 100:
                break
        return comments


def comment_json(comment: dict[str, Any]) -> dict[str, Any] | None:
    body = comment.get("body")
    if not isinstance(body, str):
        return None
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def preflight(event: dict[str, Any]) -> dict[str, str]:
    comment = event.get("comment") or {}
    issue = event.get("issue") or {}
    repository = event.get("repository") or {}
    author = comment.get("user") or {}
    should_run = (
        issue.get("number") == TRANSPORT_ISSUE
        and not issue.get("pull_request")
        and repository.get("full_name") == REPOSITORY
        and author.get("login") == ALLOWED_AUTHOR["login"]
        and author.get("id") == ALLOWED_AUTHOR["id"]
    )
    if should_run:
        try:
            value = json.loads(comment.get("body", ""))
            should_run = isinstance(value, dict) and value.get("schema") == REQUEST_SCHEMA
        except json.JSONDecodeError:
            should_run = False
    return {"should_run": "true" if should_run else "false", "concurrency_key": "task-context"}


def blob_bytes(api: GitHub, blob_sha: str) -> bytes:
    blob = api.request("GET", f"/git/blobs/{blob_sha}") or {}
    if blob.get("sha") != blob_sha or blob.get("encoding") != "base64":
        raise Reject("BLOB_NOT_FOUND", "candidate Git blob is unavailable")
    content = blob.get("content")
    if not isinstance(content, str):
        raise Reject("BLOB_NOT_FOUND", "candidate Git blob omitted content")
    try:
        data = base64.b64decode(content, validate=False)
    except Exception as exc:
        raise Reject("BLOB_NOT_FOUND", "candidate Git blob encoding is invalid") from exc
    if git_blob_sha(data) != blob_sha:
        raise Reject("BLOB_NOT_REGULAR", "candidate object does not verify as requested Git blob")
    return data


def delete_scoped_ref(api: GitHub, branch: str | None) -> None:
    if not isinstance(branch, str) or not branch.startswith(BRANCH_PREFIX):
        return
    try:
        api.request("DELETE", f"/git/refs/heads/{urllib.parse.quote(branch, safe='/')}")
    except Exception:
        pass


def classify_pr_error(exc: RuntimeError) -> Reject:
    text = str(exc).lower()
    if "failed with 403" in text and (
        "not permitted to create or approve pull requests" in text
        or "resource not accessible by integration" in text
        or "github actions" in text
    ):
        return Reject(
            "PR_CREATION_FORBIDDEN",
            "repository Actions workflow permissions block the built-in GITHUB_TOKEN from creating publication PR",
        )
    return Reject("PR_CREATION_FAILED", "scoped task-context publication PR creation failed")


class TransactionalPublisher:
    def __init__(self, api: GitHub):
        self.api = api

    def _prior(
        self,
        request: dict[str, Any],
        request_fingerprint: str,
        current_comment_id: int | None,
    ) -> dict[str, Any] | None:
        successes: list[dict[str, Any]] = []
        for comment in self.api.comments():
            obj = comment_json(comment)
            if not obj or obj.get("request_id") != request["request_id"]:
                continue
            user = comment.get("user") or {}
            if (
                obj.get("schema") == REQUEST_SCHEMA
                and comment.get("id") != current_comment_id
                and user.get("login") == ALLOWED_AUTHOR["login"]
                and user.get("id") == ALLOWED_AUTHOR["id"]
                and fingerprint(obj) != request_fingerprint
            ):
                raise Reject("REQUEST_ID_REUSE", "request_id was previously used with different normalized payload")
            if (
                obj.get("schema") == RESULT_SCHEMA
                and user.get("login") == RESULT_AUTHOR["login"]
                and user.get("id") == RESULT_AUTHOR["id"]
            ):
                validate_result(obj)
                if obj.get("request_fingerprint") != request_fingerprint:
                    raise Reject("REQUEST_ID_REUSE", "request_id already has a result for different normalized payload")
                if obj.get("status") == "success":
                    successes.append(obj)

        if not successes:
            return None
        first = successes[0]
        for other in successes[1:]:
            for key in ("expected_base", "publication_branch", "task", "artifact", "candidate", "pr", "ci_dispatch", "required_status"):
                if other.get(key) != first.get(key):
                    raise Reject("REQUEST_ID_REUSE", "successful replay results disagree on immutable publication identity")
        replay = copy.deepcopy(first)
        replay["idempotent_replay"] = True
        return replay

    def _main_head(self) -> str | None:
        ref = self.api.request("GET", "/git/ref/heads/main") or {}
        return ((ref.get("object") or {}).get("sha"))

    def publish(self, event: dict[str, Any]) -> dict[str, Any] | None:
        comment = event.get("comment") or {}
        issue = event.get("issue") or {}
        repository = event.get("repository") or {}
        author = comment.get("user") or {}
        if issue.get("pull_request") or issue.get("number") != TRANSPORT_ISSUE or repository.get("full_name") != REPOSITORY:
            return None
        if author.get("login") != ALLOWED_AUTHOR["login"] or author.get("id") != ALLOWED_AUTHOR["id"]:
            return None
        try:
            raw = json.loads(comment.get("body", ""))
        except json.JSONDecodeError:
            return None
        if isinstance(raw, dict) and raw.get("schema") == RESULT_SCHEMA:
            return None

        request_fingerprint = fingerprint(raw)
        branch = raw.get("publication_branch") if isinstance(raw, dict) else None
        branch_created = False
        pr_number: int | None = None
        try:
            request = validate_request(raw)
            request_fingerprint = fingerprint(request)
            branch = request["publication_branch"]
            replay = self._prior(request, request_fingerprint, comment.get("id"))
            if replay is not None:
                return replay

            if self._main_head() != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main does not equal expected_base")
            base_commit = self.api.request("GET", f"/git/commits/{request['expected_base']}") or {}
            base_tree = (base_commit.get("tree") or {}).get("sha")
            if not is_sha(base_tree):
                raise Reject("INTERNAL_ERROR", "base commit tree is unavailable")
            tree = self.api.request("GET", f"/git/trees/{base_tree}?recursive=1") or {}
            if tree.get("truncated") is True:
                raise Reject("INTERNAL_ERROR", "base tree response was truncated")
            by_path = {
                entry.get("path"): entry
                for entry in tree.get("tree", [])
                if isinstance(entry, dict) and isinstance(entry.get("path"), str)
            }

            artifact = request["artifact"]
            current = by_path.get(artifact["path"])
            if artifact["op"] == "add":
                if current is not None:
                    raise Reject("PATH_STATE_MISMATCH", "add target already exists at expected_base")
            else:
                if (
                    not current
                    or current.get("type") != "blob"
                    or current.get("mode") != "100644"
                    or current.get("sha") != artifact["expected_blob_sha"]
                ):
                    raise Reject("PATH_STATE_MISMATCH", "replace target base blob mismatch")

            data = blob_bytes(self.api, artifact["blob_sha"])
            if sha256(data) != artifact["content_sha256"]:
                raise Reject("PACK_INVALID", "candidate SHA-256 differs from publication request")
            validate_pack_bytes(data, request)

            branch_path = urllib.parse.quote(branch, safe="/")
            try:
                self.api.request("GET", f"/git/ref/heads/{branch_path}")
                raise Reject("BRANCH_EXISTS", "scoped publication branch already exists without exact replay result")
            except RuntimeError as exc:
                if "failed with 404" not in str(exc):
                    raise

            if self._main_head() != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main changed before publication mutation")

            new_tree = self.api.request(
                "POST",
                "/git/trees",
                {
                    "base_tree": base_tree,
                    "tree": [
                        {
                            "path": artifact["path"],
                            "mode": "100644",
                            "type": "blob",
                            "sha": artifact["blob_sha"],
                        }
                    ],
                },
            ) or {}
            tree_sha = new_tree.get("sha")
            if not is_sha(tree_sha):
                raise Reject("INTERNAL_ERROR", "candidate tree creation returned no exact SHA")

            new_commit = self.api.request(
                "POST",
                "/git/commits",
                {
                    "message": (
                        f"task-context: {request['request_id']}\n\n"
                        f"HWM-Task-Context-Request-Id: {request['request_id']}\n"
                        f"HWM-Task-Context-Request-Fingerprint: {request_fingerprint}"
                    ),
                    "tree": tree_sha,
                    "parents": [request["expected_base"]],
                },
            ) or {}
            head_sha = new_commit.get("sha")
            if not is_sha(head_sha):
                raise Reject("INTERNAL_ERROR", "candidate commit creation returned no exact SHA")
            observed_commit = self.api.request("GET", f"/git/commits/{head_sha}") or {}
            if [parent.get("sha") for parent in observed_commit.get("parents", [])] != [request["expected_base"]]:
                raise Reject("INTERNAL_ERROR", "candidate commit does not have exact single protected-base parent")
            if (observed_commit.get("tree") or {}).get("sha") != tree_sha:
                raise Reject("INTERNAL_ERROR", "candidate commit tree verification failed")

            if self._main_head() != request["expected_base"]:
                raise Reject("EXPECTED_HEAD_MISMATCH", "protected main changed before scoped ref creation")
            self.api.request("POST", "/git/refs", {"ref": f"refs/heads/{branch}", "sha": head_sha})
            branch_created = True

            try:
                pr = self.api.request(
                    "POST",
                    "/pulls",
                    {
                        "title": f"Task context publication {request['task']['task_key']} {request['request_id']}",
                        "head": branch,
                        "base": DEFAULT_BRANCH,
                        "body": (
                            "Generated canonical task-context publication. Publisher does not merge this PR. "
                            f"Exact request id: `{request['request_id']}`."
                        ),
                    },
                ) or {}
            except RuntimeError as exc:
                delete_scoped_ref(self.api, branch)
                branch_created = False
                raise classify_pr_error(exc)
            pr_number = pr.get("number")
            if not isinstance(pr_number, int) or isinstance(pr_number, bool):
                delete_scoped_ref(self.api, branch)
                branch_created = False
                raise Reject("PR_CREATION_FAILED", "publication PR creation returned no number")

            try:
                self.api.request(
                    "POST",
                    f"/actions/workflows/{CI_WORKFLOW}/dispatches",
                    {
                        "ref": branch,
                        "inputs": {"request_id": request["request_id"], "expected_head": head_sha},
                    },
                )
            except RuntimeError as exc:
                try:
                    self.api.request("PATCH", f"/pulls/{pr_number}", {"state": "closed"})
                finally:
                    delete_scoped_ref(self.api, branch)
                    branch_created = False
                raise Reject("CI_DISPATCH_FAILED", "explicit candidate bootstrap dispatch failed") from exc

            run_id: int | None = None
            for _ in range(25):
                runs = self.api.request(
                    "GET",
                    f"/actions/workflows/{CI_WORKFLOW}/runs?event=workflow_dispatch&branch={urllib.parse.quote(branch, safe='')}&per_page=20",
                ) or {}
                for run in runs.get("workflow_runs", []):
                    if (
                        run.get("head_sha") == head_sha
                        and run.get("event") == "workflow_dispatch"
                        and run.get("path") == CI_PATH
                    ):
                        run_id = run.get("id")
                        break
                if isinstance(run_id, int):
                    break
                time.sleep(1)
            if not isinstance(run_id, int):
                try:
                    self.api.request("PATCH", f"/pulls/{pr_number}", {"state": "closed"})
                finally:
                    delete_scoped_ref(self.api, branch)
                    branch_created = False
                raise Reject("CI_DISPATCH_FAILED", "exact candidate bootstrap run could not be associated")

            result = {
                "schema": RESULT_SCHEMA,
                "request_id": request["request_id"],
                "status": "success",
                "repository": REPOSITORY,
                "transport_issue": TRANSPORT_ISSUE,
                "expected_base": request["expected_base"],
                "publication_branch": branch,
                "task": copy.deepcopy(request["task"]),
                "artifact": copy.deepcopy(artifact),
                "request_fingerprint": request_fingerprint,
                "idempotent_replay": False,
                "candidate": {
                    "commit_sha": head_sha,
                    "tree_sha": tree_sha,
                    "parent_sha": request["expected_base"],
                    "parent_count": 1,
                },
                "pr": {
                    "number": pr_number,
                    "base_ref": DEFAULT_BRANCH,
                    "head_ref": branch,
                    "head_sha": head_sha,
                },
                "ci_dispatch": {
                    "workflow": CI_WORKFLOW,
                    "run_id": run_id,
                    "head_sha": head_sha,
                    "required_check": REQUIRED_CHECK,
                },
                "required_status": {
                    "context": REQUIRED_CHECK,
                    "integration_id": REQUIRED_INTEGRATION_ID,
                    "creator_login": RESULT_AUTHOR["login"],
                    "creator_id": RESULT_AUTHOR["id"],
                },
                "error": None,
            }
            validate_result(result)
            return result
        except Reject as exc:
            if branch_created:
                delete_scoped_ref(self.api, branch)
            return error_result(raw, exc.code, exc.message, request_fingerprint)
        except Exception:
            if branch_created:
                delete_scoped_ref(self.api, branch)
            return error_result(raw, "INTERNAL_ERROR", "publisher encountered a sanitized internal failure", request_fingerprint)


def cleanup(event: dict[str, Any], api: GitHub) -> None:
    pr = event.get("pull_request") or {}
    head = pr.get("head") or {}
    repository = head.get("repo") or {}
    branch = head.get("ref")
    if (
        pr.get("merged") is True
        or (pr.get("base") or {}).get("ref") != DEFAULT_BRANCH
        or repository.get("full_name") != REPOSITORY
        or not isinstance(branch, str)
        or not branch.startswith(BRANCH_PREFIX)
    ):
        return
    api.request("DELETE", f"/git/refs/heads/{urllib.parse.quote(branch, safe='/')}")


def write_outputs(values: dict[str, str]) -> None:
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        for key, value in values.items():
            print(f"{key}={value}")
        return
    with open(output, "a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in {"preflight", "publish", "cleanup"}:
        print("usage: task_context_publisher.py {preflight|publish|cleanup} EVENT_JSON", file=sys.stderr)
        return 2
    with open(argv[2], "r", encoding="utf-8") as handle:
        event = json.load(handle)
    if argv[1] == "preflight":
        write_outputs(preflight(event))
        return 0

    token = os.environ.pop("HWM_TASK_CONTEXT_PUBLISHER_TOKEN", None)
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
