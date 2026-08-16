#!/usr/bin/env python3
"""Credentialed upload boundary for I09 task-context staging.

The repository and both mutation endpoints are compile-time constants. This file
intentionally has no generic GitHub method/path wrapper.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

REPOSITORY = "Dsamofalov/hwm-context"
TRANSPORT_ISSUE = 27
BLOB_POST_URL = "https://api.github.com/repos/Dsamofalov/hwm-context/git/blobs"
BLOB_READ_URL_PREFIX = "https://api.github.com/repos/Dsamofalov/hwm-context/git/blobs/"
RESULT_POST_URL = "https://api.github.com/repos/Dsamofalov/hwm-context/issues/27/comments"
RESULT_SCHEMA_PATH = Path("trusted-control/schemas/task-context-stage-result.v1.schema.json")
CONTEXT_FILE_NAME = "context.json"
TOKEN_ENV = "HWM_TASK_CONTEXT_STAGE_TOKEN"


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _add_headers(request: urllib.request.Request, token: str, *, json_body: bool = False) -> None:
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("Authorization", f"Bearer {token}")
    if json_body:
        request.add_header("Content-Type", "application/json")


def _create_exact_blob(token: str, data: bytes) -> str:
    payload = canonical_json({"content": base64.b64encode(data).decode("ascii"), "encoding": "base64"}).encode("utf-8")
    request = urllib.request.Request(BLOB_POST_URL, data=payload, method="POST")
    _add_headers(request, token, json_body=True)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            obj = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"blob creation failed with {exc.code}") from exc
    sha = obj.get("sha") if isinstance(obj, dict) else None
    if not isinstance(sha, str):
        raise RuntimeError("blob creation returned no SHA")
    return sha


def _read_exact_blob(token: str, blob_sha: str) -> bytes:
    if not isinstance(blob_sha, str) or len(blob_sha) != 40 or any(ch not in "0123456789abcdef" for ch in blob_sha):
        raise RuntimeError("readback blob SHA malformed")
    request = urllib.request.Request(BLOB_READ_URL_PREFIX + blob_sha, method="GET")
    _add_headers(request, token)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            obj = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"blob readback failed with {exc.code}") from exc
    if not isinstance(obj, dict) or obj.get("sha") != blob_sha or obj.get("encoding") != "base64" or not isinstance(obj.get("content"), str):
        raise RuntimeError("blob readback metadata mismatch")
    return base64.b64decode(obj["content"], validate=False)


def _post_normalized_result(token: str, result: dict[str, Any]) -> int:
    payload = canonical_json({"body": canonical_json(result)}).encode("utf-8")
    request = urllib.request.Request(RESULT_POST_URL, data=payload, method="POST")
    _add_headers(request, token, json_body=True)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            obj = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"result comment failed with {exc.code}") from exc
    comment_id = obj.get("id") if isinstance(obj, dict) else None
    if not isinstance(comment_id, int) or isinstance(comment_id, bool):
        raise RuntimeError("result comment returned no id")
    return comment_id


def _validate_result(result: dict[str, Any]) -> None:
    schema = json.loads(RESULT_SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result)


def _as_upload_error(result: dict[str, Any], message: str) -> dict[str, Any]:
    out = copy.deepcopy(result)
    out["status"] = "error"
    out["artifact"] = None
    out["idempotent_replay"] = False
    out["error"] = {"code": "BLOB_UPLOAD_REJECTED", "message": " ".join(message.split())[:240], "retryable": False}
    return out


def _validate_intent_shape(intent: Any) -> str:
    if not isinstance(intent, dict) or intent.get("action") not in {"stage", "result_only", "replay"}:
        raise RuntimeError("upload intent action is not allowlisted")
    action = intent["action"]
    if action == "replay":
        if set(intent) != {"action", "result"} or not isinstance(intent.get("result"), dict):
            raise RuntimeError("replay intent malformed")
        return action
    if action == "result_only":
        if set(intent) != {"action", "result"} or not isinstance(intent.get("result"), dict):
            raise RuntimeError("result-only intent malformed")
        return action
    expected_keys = {"action", "expected_context_sha256", "expected_git_blob_sha", "expected_byte_length", "result_draft"}
    if set(intent) != expected_keys or not isinstance(intent.get("result_draft"), dict):
        raise RuntimeError("stage intent fields are not closed")
    expected_sha256 = intent["expected_context_sha256"]
    expected_blob = intent["expected_git_blob_sha"]
    expected_length = intent["expected_byte_length"]
    if not isinstance(expected_sha256, str) or len(expected_sha256) != 64 or not isinstance(expected_blob, str) or len(expected_blob) != 40 or not isinstance(expected_length, int) or isinstance(expected_length, bool) or expected_length < 1:
        raise RuntimeError("stage intent identities malformed")
    return action


def upload_intent(intent_path: Path) -> dict[str, Any]:
    intent = json.loads(intent_path.read_text(encoding="utf-8"))
    action = _validate_intent_shape(intent)

    if action == "replay":
        replay = copy.deepcopy(intent["result"])
        replay["idempotent_replay"] = True
        print(canonical_json(replay))
        return replay

    if action == "stage":
        expected_sha256 = intent["expected_context_sha256"]
        expected_blob = intent["expected_git_blob_sha"]
        expected_length = intent["expected_byte_length"]
        context_path = intent_path.parent / CONTEXT_FILE_NAME
        data = context_path.read_bytes()
        if len(data) != expected_length or sha256(data) != expected_sha256 or git_blob_sha(data) != expected_blob:
            raise RuntimeError("local compiled bytes differ from closed stage intent")

    token = os.environ.get(TOKEN_ENV, "")
    if not token:
        raise RuntimeError("job-scoped staging token missing")

    if action == "result_only":
        result = intent["result"]
        _validate_result(result)
        comment_id = _post_normalized_result(token, result)
        print(f"result_comment_id={comment_id}")
        return result

    result = copy.deepcopy(intent["result_draft"])
    try:
        returned_sha = _create_exact_blob(token, data)
        if returned_sha != expected_blob:
            raise RuntimeError("GitHub returned blob SHA differs from independently computed SHA")
        readback = _read_exact_blob(token, expected_blob)
        if readback != data or sha256(readback) != expected_sha256 or git_blob_sha(readback) != expected_blob:
            raise RuntimeError("created Git blob failed byte-exact readback verification")
        result["artifact"] = {
            "byte_length": expected_length,
            "context_sha256": expected_sha256,
            "git_blob_sha": expected_blob,
            "unattached": True,
            "readback_byte_equal": True,
            "readback_sha256": expected_sha256,
            "readback_git_blob_sha": expected_blob,
        }
        _validate_result(result)
    except Exception as exc:
        result = _as_upload_error(result, str(exc) or "credentialed blob upload failed")
        _validate_result(result)

    comment_id = _post_normalized_result(token, result)
    print(f"result_comment_id={comment_id}")
    print(canonical_json(result))
    return result


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] != "upload":
        print("usage: task_context_stage_uploader.py upload INTENT", file=sys.stderr)
        return 2
    try:
        upload_intent(Path(argv[2]))
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
