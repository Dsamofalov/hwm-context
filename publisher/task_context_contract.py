#!/usr/bin/env python3
"""Closed I09 task-context publication contract for hwm-context."""
from __future__ import annotations

import copy
import hashlib
import json
import re
from typing import Any

REQUEST_SCHEMA = "hwm-task-context-publish-request/v1"
RESULT_SCHEMA = "hwm-task-context-publish-result/v1"
PACK_SCHEMA = "hwm-task-context-pack/v1"
REPOSITORY = "Dsamofalov/hwm-context"
ISSUE_REPOSITORY = "Dsamofalov/hwm-control"
TRANSPORT_ISSUE = 27
ALLOWED_AUTHOR = {"login": "Dsamofalov", "id": 25666939}
RESULT_AUTHOR = {"login": "github-actions[bot]", "id": 41898282}
DEFAULT_BRANCH = "main"
CI_WORKFLOW = "repository-bootstrap-ci.yml"
CI_PATH = ".github/workflows/repository-bootstrap-ci.yml"
REQUIRED_CHECK = "bootstrap"
REQUIRED_INTEGRATION_ID = 15368
BRANCH_PREFIX = "publisher/task-context/"
MAX_BLOB_BYTES = 4 * 1024 * 1024

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")
REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,95}$")
SOURCE_REQUEST_RE = re.compile(r"^tcr1-[0-9a-f]{64}$")
TASK_RE = re.compile(r"^I[0-9]{2}-[0-9]{4}$")
BRANCH_RE = re.compile(r"^publisher/task-context/(i[0-9]{2}-[0-9]{4})/[a-z0-9][a-z0-9._-]{7,95}$")

FORBIDDEN_PUBLIC_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bauthorization\s*:\s*bearer\s+\S+", re.I),
    re.compile(r"\bset-cookie\s*:\s*\S+", re.I),
    re.compile(
        r"\b(?:password|api[_-]?key|access[_-]?token|refresh[_-]?token|"
        r"session(?:id|_token)?|client[_-]?secret)\s*[:=]\s*['\"]?[^\s'\"]{8,}",
        re.I,
    ),
)

ERROR_CODES = {
    "INVALID_SCHEMA",
    "INVALID_TRANSPORT",
    "UNAUTHORIZED_AUTHOR",
    "REPOSITORY_NOT_ALLOWED",
    "FORBIDDEN_TARGET",
    "FORBIDDEN_PATH",
    "PATH_STATE_MISMATCH",
    "BLOB_NOT_FOUND",
    "BLOB_NOT_REGULAR",
    "PACK_INVALID",
    "UNSAFE_PAYLOAD",
    "EXPECTED_HEAD_MISMATCH",
    "BRANCH_EXISTS",
    "REQUEST_ID_REUSE",
    "PR_CREATION_FAILED",
    "PR_CREATION_FORBIDDEN",
    "CI_DISPATCH_FAILED",
    "STRICT_GATE_REJECTED",
    "INTERNAL_ERROR",
}

SERIALIZATION = {
    "profile": "hwm-canonical-json/v1",
    "artifact": "context.json",
    "encoding": "UTF-8",
    "bom": False,
    "object_key_order": "lexicographic_unicode_codepoint",
    "separators": "comma_colon_no_whitespace",
    "trailing_lf": True,
    "unicode_normalization": "none",
    "non_finite_numbers": "reject",
    "compiler_controlled_array_order": "contract_defined",
    "context_markdown": "not_defined_in_v1",
}

TOP_PACK_FIELDS = {
    "schema",
    "request_binding",
    "task",
    "issue_snapshot",
    "product",
    "project_state",
    "historical_ledger",
    "knowledge_deltas",
    "authority_model",
    "selection",
    "freshness",
    "sources",
    "public_data",
    "serialization",
}


class Reject(Exception):
    def __init__(self, code: str, message: str):
        if code not in ERROR_CODES:
            code, message = "INTERNAL_ERROR", "publisher rejected an unclassified failure"
        super().__init__(message)
        self.code = code
        self.message = " ".join(str(message).split())[:240]


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def is_hex256(value: Any) -> bool:
    return isinstance(value, str) and HEX_RE.fullmatch(value) is not None


def task_issue_number(task_key: str) -> int:
    return int(task_key.rsplit("-", 1)[1])


def task_path(task_key: str) -> str:
    return f"tasks/{task_key}/context.json"


def _json_no_constants(text: str) -> Any:
    def reject_constant(value: str) -> None:
        raise ValueError(f"non-finite number {value}")

    return json.loads(text, parse_constant=reject_constant)


def _validate_public_text(text: str) -> None:
    if any(pattern.search(text) for pattern in FORBIDDEN_PUBLIC_PATTERNS):
        raise Reject("UNSAFE_PAYLOAD", "candidate pack violates public-data policy")


def validate_pack_bytes(
    data: bytes,
    request: dict[str, Any] | None = None,
    *,
    expected_task_key: str | None = None,
) -> dict[str, Any]:
    if not data or len(data) > MAX_BLOB_BYTES or b"\x00" in data:
        raise Reject("UNSAFE_PAYLOAD", "candidate pack violates bounded UTF-8 text policy")
    if data.startswith(b"\xef\xbb\xbf") or not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise Reject("PACK_INVALID", "context.json must be UTF-8 without BOM and exactly one trailing LF")
    try:
        text = data.decode("utf-8")
        pack = _json_no_constants(text)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as exc:
        raise Reject("PACK_INVALID", "context.json is not canonical JSON") from exc

    _validate_public_text(text)
    if not isinstance(pack, dict) or set(pack) != TOP_PACK_FIELDS or pack.get("schema") != PACK_SCHEMA:
        raise Reject("PACK_INVALID", "pack schema/top-level fields mismatch")
    if canonical_json(pack).encode("utf-8") + b"\n" != data:
        raise Reject("PACK_INVALID", "context.json bytes are not hwm-canonical-json/v1")

    task = pack.get("task")
    issue = pack.get("issue_snapshot")
    binding = pack.get("request_binding")
    if not isinstance(task, dict) or set(task) != {"task_key", "issue_repository", "issue_number"}:
        raise Reject("PACK_INVALID", "pack task binding malformed")
    task_key = task.get("task_key")
    issue_number = task.get("issue_number")
    if (
        not isinstance(task_key, str)
        or TASK_RE.fullmatch(task_key) is None
        or task.get("issue_repository") != ISSUE_REPOSITORY
        or not isinstance(issue_number, int)
        or isinstance(issue_number, bool)
        or task_issue_number(task_key) != issue_number
    ):
        raise Reject("PACK_INVALID", "pack task/Issue identity mismatch")
    if expected_task_key is not None and task_key != expected_task_key:
        raise Reject("PACK_INVALID", "pack task key does not match target path")
    if not isinstance(issue, dict) or issue.get("repository") != ISSUE_REPOSITORY or issue.get("issue_number") != issue_number:
        raise Reject("PACK_INVALID", "pack Issue snapshot identity mismatch")
    if (
        not isinstance(binding, dict)
        or set(binding) != {"request_id", "request_sha256"}
        or not isinstance(binding.get("request_id"), str)
        or SOURCE_REQUEST_RE.fullmatch(binding["request_id"]) is None
        or not is_hex256(binding.get("request_sha256"))
    ):
        raise Reject("PACK_INVALID", "pack source request binding malformed")
    if pack.get("serialization") != SERIALIZATION:
        raise Reject("PACK_INVALID", "pack serialization contract mismatch")

    freshness = pack.get("freshness")
    if (
        not isinstance(freshness, dict)
        or freshness.get("policy") != "hwm-exact-bound-freshness/v1"
        or freshness.get("status") != "fresh"
        or freshness.get("on_mismatch") != "reject"
        or freshness.get("no_implicit_head_substitution") is not True
    ):
        raise Reject("PACK_INVALID", "pack freshness contract mismatch")
    checks = freshness.get("checks")
    if not isinstance(checks, list) or not checks:
        raise Reject("PACK_INVALID", "pack freshness checks are missing")
    for check in checks:
        if not isinstance(check, dict) or check.get("status") != "match" or check.get("expected") != check.get("observed"):
            raise Reject("PACK_INVALID", "pack freshness proof is stale or malformed")

    public_data = pack.get("public_data")
    if (
        not isinstance(public_data, dict)
        or public_data.get("policy") != "hwm-public-data/v1"
        or public_data.get("classification") != "public-disclosure-safe"
        or public_data.get("on_violation") != "reject"
    ):
        raise Reject("PACK_INVALID", "pack public-data declaration mismatch")

    authority = pack.get("authority_model")
    if (
        not isinstance(authority, dict)
        or authority.get("current_state_is_authoritative") is not True
        or authority.get("historical_is_not_current_state") is not True
        or authority.get("derived_context_is_not_authority") is not True
        or authority.get("llm_is_not_deterministic_authority") is not True
    ):
        raise Reject("PACK_INVALID", "pack authority model mismatch")

    if request is not None:
        requested_task = request["task"]
        expected_task = {
            "task_key": requested_task["task_key"],
            "issue_repository": requested_task["issue_repository"],
            "issue_number": requested_task["issue_number"],
        }
        if task != expected_task:
            raise Reject("PACK_INVALID", "pack task differs from publication request")
        if (
            binding["request_id"] != requested_task["source_request_id"]
            or binding["request_sha256"] != requested_task["source_request_sha256"]
        ):
            raise Reject("PACK_INVALID", "pack source request binding differs from publication request")
    return pack


def validate_request(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise Reject("INVALID_SCHEMA", "request must be one JSON object")
    top = {
        "schema",
        "request_id",
        "repository",
        "transport_issue",
        "expected_base",
        "publication_branch",
        "task",
        "artifact",
        "candidate",
        "ci",
    }
    if set(obj) != top or obj.get("schema") != REQUEST_SCHEMA:
        raise Reject("INVALID_SCHEMA", "request fields/schema do not match task-context-publish-v1")
    if not isinstance(obj.get("request_id"), str) or REQUEST_ID_RE.fullmatch(obj["request_id"]) is None:
        raise Reject("INVALID_SCHEMA", "request_id malformed")
    if obj.get("repository") != REPOSITORY:
        raise Reject("REPOSITORY_NOT_ALLOWED", "target repository is not allowlisted")
    if obj.get("transport_issue") != TRANSPORT_ISSUE:
        raise Reject("INVALID_TRANSPORT", "request is not bound to task-context transport Issue")
    if not is_sha(obj.get("expected_base")):
        raise Reject("INVALID_SCHEMA", "expected_base must be exact lowercase SHA")

    task = obj.get("task")
    task_fields = {"task_key", "issue_repository", "issue_number", "source_request_id", "source_request_sha256"}
    if not isinstance(task, dict) or set(task) != task_fields:
        raise Reject("INVALID_SCHEMA", "task publication binding malformed")
    task_key = task.get("task_key")
    issue_number = task.get("issue_number")
    if (
        not isinstance(task_key, str)
        or TASK_RE.fullmatch(task_key) is None
        or task.get("issue_repository") != ISSUE_REPOSITORY
        or not isinstance(issue_number, int)
        or isinstance(issue_number, bool)
        or task_issue_number(task_key) != issue_number
        or not isinstance(task.get("source_request_id"), str)
        or SOURCE_REQUEST_RE.fullmatch(task["source_request_id"]) is None
        or not is_hex256(task.get("source_request_sha256"))
    ):
        raise Reject("INVALID_SCHEMA", "task key/Issue/source-request binding mismatch")

    branch = obj.get("publication_branch")
    branch_match = BRANCH_RE.fullmatch(branch) if isinstance(branch, str) else None
    if branch in {DEFAULT_BRANCH, "main"} or branch_match is None or branch_match.group(1) != task_key.lower():
        raise Reject("FORBIDDEN_TARGET", "publication branch is outside exact task-scoped namespace")

    artifact = obj.get("artifact")
    if not isinstance(artifact, dict):
        raise Reject("INVALID_SCHEMA", "artifact binding malformed")
    op = artifact.get("op")
    if op == "add":
        artifact_fields = {"op", "path", "blob_sha", "content_sha256", "mode", "pack_schema"}
    elif op == "replace":
        artifact_fields = {"op", "path", "blob_sha", "content_sha256", "mode", "pack_schema", "expected_blob_sha"}
    else:
        raise Reject("INVALID_SCHEMA", "task-context publication permits only add/replace")
    if set(artifact) != artifact_fields:
        raise Reject("INVALID_SCHEMA", "artifact fields do not match operation")
    if artifact.get("path") != task_path(task_key):
        raise Reject("FORBIDDEN_PATH", "only exact tasks/<task-key>/context.json is allowed")
    if artifact.get("mode") != "100644":
        raise Reject("BLOB_NOT_REGULAR", "task context v1 requires regular 100644 blob")
    if artifact.get("pack_schema") != PACK_SCHEMA or not is_sha(artifact.get("blob_sha")) or not is_hex256(artifact.get("content_sha256")):
        raise Reject("INVALID_SCHEMA", "artifact digest/schema malformed")
    if op == "replace" and not is_sha(artifact.get("expected_blob_sha")):
        raise Reject("INVALID_SCHEMA", "replace requires exact expected_blob_sha")

    expected_candidate = {
        "parent_sha": obj["expected_base"],
        "parent_count": 1,
        "tree_policy": "base-plus-exact-task-context-blob",
    }
    if obj.get("candidate") != expected_candidate:
        raise Reject("INVALID_SCHEMA", "candidate parent/tree semantics mismatch")
    if obj.get("ci") != {
        "workflow": CI_WORKFLOW,
        "required_check": REQUIRED_CHECK,
        "status_integration_id": REQUIRED_INTEGRATION_ID,
    }:
        raise Reject("INVALID_SCHEMA", "CI/status provenance declaration mismatch")
    return obj


def validate_result(obj: Any) -> dict[str, Any]:
    if not isinstance(obj, dict):
        raise Reject("INVALID_SCHEMA", "result must be one JSON object")
    top = {
        "schema",
        "request_id",
        "status",
        "repository",
        "transport_issue",
        "expected_base",
        "publication_branch",
        "task",
        "artifact",
        "request_fingerprint",
        "idempotent_replay",
        "candidate",
        "pr",
        "ci_dispatch",
        "required_status",
        "error",
    }
    if set(obj) != top or obj.get("schema") != RESULT_SCHEMA:
        raise Reject("INVALID_SCHEMA", "result fields/schema do not match task-context-publish-result-v1")
    if obj.get("status") not in {"success", "error"} or not is_hex256(obj.get("request_fingerprint")):
        raise Reject("INVALID_SCHEMA", "result status/fingerprint malformed")
    if not isinstance(obj.get("idempotent_replay"), bool):
        raise Reject("INVALID_SCHEMA", "result replay marker malformed")
    if obj.get("repository") != REPOSITORY or obj.get("transport_issue") != TRANSPORT_ISSUE:
        raise Reject("INVALID_SCHEMA", "result repository/transport mismatch")

    if obj["status"] == "success":
        candidate = obj.get("candidate")
        pr = obj.get("pr")
        dispatch = obj.get("ci_dispatch")
        status = obj.get("required_status")
        if (
            not isinstance(candidate, dict)
            or set(candidate) != {"commit_sha", "tree_sha", "parent_sha", "parent_count"}
            or not is_sha(candidate.get("commit_sha"))
            or not is_sha(candidate.get("tree_sha"))
            or not is_sha(candidate.get("parent_sha"))
            or candidate.get("parent_count") != 1
        ):
            raise Reject("INVALID_SCHEMA", "result candidate provenance malformed")
        if (
            not isinstance(pr, dict)
            or set(pr) != {"number", "base_ref", "head_ref", "head_sha"}
            or not isinstance(pr.get("number"), int)
            or isinstance(pr.get("number"), bool)
            or pr.get("base_ref") != DEFAULT_BRANCH
            or not is_sha(pr.get("head_sha"))
        ):
            raise Reject("INVALID_SCHEMA", "result PR provenance malformed")
        if (
            not isinstance(dispatch, dict)
            or set(dispatch) != {"workflow", "run_id", "head_sha", "required_check"}
            or dispatch.get("workflow") != CI_WORKFLOW
            or not isinstance(dispatch.get("run_id"), int)
            or isinstance(dispatch.get("run_id"), bool)
            or dispatch.get("run_id") < 1
            or not is_sha(dispatch.get("head_sha"))
            or dispatch.get("required_check") != REQUIRED_CHECK
        ):
            raise Reject("INVALID_SCHEMA", "result CI provenance malformed")
        if status != {
            "context": REQUIRED_CHECK,
            "integration_id": REQUIRED_INTEGRATION_ID,
            "creator_login": RESULT_AUTHOR["login"],
            "creator_id": RESULT_AUTHOR["id"],
        }:
            raise Reject("INVALID_SCHEMA", "result status provenance malformed")
        if obj.get("error") is not None:
            raise Reject("INVALID_SCHEMA", "success result cannot carry error")
    else:
        if any(obj.get(key) is not None for key in ("candidate", "pr", "ci_dispatch", "required_status")):
            raise Reject("INVALID_SCHEMA", "error result cannot claim publication provenance")
        error = obj.get("error")
        if not isinstance(error, dict) or set(error) != {"code", "message"} or error.get("code") not in ERROR_CODES:
            raise Reject("INVALID_SCHEMA", "typed error result malformed")
    return obj


def error_result(request: Any, code: str, message: str, fp: str | None = None) -> dict[str, Any]:
    task = request.get("task") if isinstance(request, dict) and isinstance(request.get("task"), dict) else None
    artifact = request.get("artifact") if isinstance(request, dict) and isinstance(request.get("artifact"), dict) else None
    return {
        "schema": RESULT_SCHEMA,
        "request_id": request.get("request_id", "invalid-request") if isinstance(request, dict) else "invalid-request",
        "status": "error",
        "repository": REPOSITORY,
        "transport_issue": TRANSPORT_ISSUE,
        "expected_base": request.get("expected_base") if isinstance(request, dict) and is_sha(request.get("expected_base")) else None,
        "publication_branch": request.get("publication_branch") if isinstance(request, dict) and isinstance(request.get("publication_branch"), str) else None,
        "task": copy.deepcopy(task),
        "artifact": copy.deepcopy(artifact),
        "request_fingerprint": fp or fingerprint(request),
        "idempotent_replay": False,
        "candidate": None,
        "pr": None,
        "ci_dispatch": None,
        "required_status": None,
        "error": {"code": code if code in ERROR_CODES else "INTERNAL_ERROR", "message": " ".join(str(message).split())[:240]},
    }
