#!/usr/bin/env python3
"""Trusted compiler-backed preparation for I09 task-context blob staging.

This module never receives or uses a GitHub mutation credential. It performs only
public read-only GitHub observations, validates the small stage request, imports
the compiler from an independently verified protected hwm-control checkout,
compiles twice, and writes inert bytes plus a local upload intent.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Mapping

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from publisher.task_context_contract import MAX_BLOB_BYTES, validate_pack_bytes

STAGE_REQUEST_SCHEMA = "hwm-task-context-stage-request/v1"
STAGE_RESULT_SCHEMA = "hwm-task-context-stage-result/v1"
TASK_REQUEST_SCHEMA = "hwm-task-context-request/v1"
REPOSITORY = "Dsamofalov/hwm-context"
CONTROL_REPOSITORY = "Dsamofalov/hwm-control"
PRODUCT_REPOSITORY = "Dsamofalov/hwm_predictor"
TRANSPORT_ISSUE = 27
ALLOWED_AUTHOR = {"login": "Dsamofalov", "id": 25666939}
RESULT_AUTHOR = {"login": "github-actions[bot]", "id": 41898282}
ALLOWED_REPOSITORIES = {REPOSITORY, CONTROL_REPOSITORY, PRODUCT_REPOSITORY}
REQUEST_ID_RE = re.compile(r"^tcs1-[0-9a-f]{64}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
HEX_RE = re.compile(r"^[0-9a-f]{64}$")

COMPILER_PATH = "control/task_context_compiler.py"
CORE_PATH = "control/task_context_core.py"
REQUEST_SCHEMA_PATH = "schemas/task-context-request.v1.schema.json"
PACK_SCHEMA_PATH = "schemas/task-context-pack.v1.schema.json"
STAGE_REQUEST_SCHEMA_PATH = "schemas/task-context-stage-request.v1.schema.json"
STAGE_RESULT_SCHEMA_PATH = "schemas/task-context-stage-result.v1.schema.json"

ERROR_CODES = {
    "INVALID_SCHEMA",
    "INVALID_TRANSPORT",
    "UNAUTHORIZED_AUTHOR",
    "REPOSITORY_NOT_ALLOWED",
    "STALE_CONTROL_HEAD",
    "STALE_CONTEXT_HEAD",
    "STALE_PRODUCT_HEAD",
    "TRUSTED_CODE_MISMATCH",
    "SOURCE_REQUEST_ID_MISMATCH",
    "SOURCE_REQUEST_SHA_MISMATCH",
    "COMPILATION_REJECTED",
    "DOUBLE_COMPILE_MISMATCH",
    "EXPECTED_CONTEXT_MISMATCH",
    "EXPECTED_BLOB_MISMATCH",
    "PACK_TOO_LARGE",
    "REQUEST_ID_REUSE",
    "INTERNAL_ERROR",
}


class Reject(Exception):
    def __init__(self, code: str, message: str, *, retryable: bool = False):
        if code not in ERROR_CODES:
            code, message, retryable = "INTERNAL_ERROR", "stager rejected an unclassified failure", False
        super().__init__(message)
        self.code = code
        self.message = " ".join(str(message).split())[:240]
        self.retryable = bool(retryable)


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def fingerprint(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def _valid_sha(value: Any) -> bool:
    return isinstance(value, str) and SHA_RE.fullmatch(value) is not None


def _valid_hex(value: Any) -> bool:
    return isinstance(value, str) and HEX_RE.fullmatch(value) is not None


class PublicGitHubReader:
    """Unauthenticated read-only provider for public authoritative inputs."""

    api = "https://api.github.com"

    def _get(self, url: str) -> Any:
        request = urllib.request.Request(url, method="GET")
        request.add_header("Accept", "application/vnd.github+json")
        request.add_header("X-GitHub-Api-Version", "2022-11-28")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f"public GitHub read failed with {exc.code}") from exc
        return None if not raw else json.loads(raw.decode("utf-8"))

    def _repo_url(self, repository: str, suffix: str) -> str:
        if repository not in ALLOWED_REPOSITORIES:
            raise Reject("REPOSITORY_NOT_ALLOWED", "source repository is not allowlisted")
        return f"{self.api}/repos/{repository}{suffix}"

    def observe_head(self, repository: str) -> str:
        obj = self._get(self._repo_url(repository, "/git/ref/heads/main")) or {}
        sha = ((obj.get("object") or {}).get("sha"))
        if not _valid_sha(sha):
            raise Reject("INTERNAL_ERROR", "authoritative main head observation malformed", retryable=True)
        return sha

    def fetch_issue_raw(self, repository: str, issue_number: int) -> dict[str, Any]:
        if repository != CONTROL_REPOSITORY or not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number < 1:
            raise Reject("REPOSITORY_NOT_ALLOWED", "task Issue source is outside the exact control repository")
        obj = self._get(self._repo_url(repository, f"/issues/{issue_number}")) or {}
        return {
            "title": obj.get("title"),
            "body": obj.get("body") or "",
            "updated_at": obj.get("updated_at"),
            "state": obj.get("state"),
            "state_reason": obj.get("state_reason"),
            "labels": [item.get("name") for item in obj.get("labels", []) if isinstance(item, dict)],
            "assignees": [item.get("login") for item in obj.get("assignees", []) if isinstance(item, dict)],
            "milestone_number": ((obj.get("milestone") or {}).get("number")),
        }

    def fetch_blob_bytes(self, repository: str, commit: str, path: str) -> tuple[bytes, str]:
        if not _valid_sha(commit) or not isinstance(path, str) or not path or path.startswith("/") or "\x00" in path:
            raise Reject("INVALID_SCHEMA", "exact blob binding is malformed")
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_ref = urllib.parse.quote(commit, safe="")
        obj = self._get(self._repo_url(repository, f"/contents/{encoded_path}?ref={encoded_ref}")) or {}
        if obj.get("type") != "file" or obj.get("encoding") != "base64" or not _valid_sha(obj.get("sha")):
            raise RuntimeError("exact public blob is unavailable")
        content = obj.get("content")
        if not isinstance(content, str):
            raise RuntimeError("exact public blob omitted content")
        data = base64.b64decode(content, validate=False)
        if git_blob_sha(data) != obj["sha"]:
            raise RuntimeError("GitHub content response failed Git blob verification")
        return data, obj["sha"]

    def comments(self) -> list[dict[str, Any]]:
        comments: list[dict[str, Any]] = []
        for page in range(1, 11):
            batch = self._get(self._repo_url(REPOSITORY, f"/issues/{TRANSPORT_ISSUE}/comments?per_page=100&page={page}")) or []
            if not isinstance(batch, list):
                raise RuntimeError("transport comment listing malformed")
            comments.extend(batch)
            if len(batch) < 100:
                break
        return comments


class CompilerProvider:
    def __init__(self, reader: PublicGitHubReader, compiler: Any):
        self.reader = reader
        self.compiler = compiler
        self.head_observations: dict[str, str] = {}

    def observe_head(self, repository: str) -> str:
        value = self.reader.observe_head(repository)
        self.head_observations[repository] = value
        return value

    def fetch_issue(self, repository: str, issue_number: int) -> Mapping[str, Any]:
        return self.reader.fetch_issue_raw(repository, issue_number)

    def fetch_blob(self, repository: str, commit: str, path: str) -> Any:
        try:
            data, blob_sha = self.reader.fetch_blob_bytes(repository, commit, path)
        except Reject:
            raise
        except Exception as exc:
            raise self.compiler.SourceFetchError("SOURCE_FETCH_ERROR", "exact public source retrieval failed", retryable=True) from exc
        return self.compiler.ExactBlob(data, blob_sha)


def _git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise Reject("TRUSTED_CODE_MISMATCH", "trusted control checkout failed local Git verification")
    return completed.stdout.strip()


def _local_blob(root: Path, path: str) -> str:
    full = root / path
    if not full.is_file() or full.is_symlink():
        raise Reject("TRUSTED_CODE_MISMATCH", f"trusted compiler path is not a regular file: {path}")
    return _git(root, "hash-object", "--", path)


def load_trusted_compiler(control_root: Path, request: Mapping[str, Any]) -> tuple[Any, dict[str, Any]]:
    compiler_binding = request["compiler"]
    head = _git(control_root, "rev-parse", "HEAD")
    if head != request["expected_control_main"] or head != compiler_binding["commit"]:
        raise Reject("TRUSTED_CODE_MISMATCH", "trusted control checkout is not the exact protected commit")
    expected = {
        COMPILER_PATH: compiler_binding["compiler_blob_sha"],
        CORE_PATH: compiler_binding["core_blob_sha"],
        REQUEST_SCHEMA_PATH: compiler_binding["request_schema_blob_sha"],
        PACK_SCHEMA_PATH: compiler_binding["pack_schema_blob_sha"],
    }
    for path, blob_sha in expected.items():
        if _local_blob(control_root, path) != blob_sha:
            raise Reject("TRUSTED_CODE_MISMATCH", f"trusted compiler contract blob mismatch: {path}")

    root_text = str(control_root.resolve())
    if root_text not in sys.path:
        sys.path.insert(0, root_text)
    for name in ("control.task_context_compiler", "control.task_context_core", "control"):
        sys.modules.pop(name, None)
    compiler = importlib.import_module("control.task_context_compiler")
    module_path = Path(compiler.__file__).resolve()
    if control_root.resolve() not in module_path.parents or module_path != (control_root / COMPILER_PATH).resolve():
        raise Reject("TRUSTED_CODE_MISMATCH", "compiler import did not originate from the exact trusted checkout")
    if not callable(getattr(compiler, "compile_task_context", None)):
        raise Reject("TRUSTED_CODE_MISMATCH", "trusted compiler callable is unavailable")
    provenance = {
        "repository": CONTROL_REPOSITORY,
        "commit": head,
        "compiler_blob_sha": expected[COMPILER_PATH],
        "core_blob_sha": expected[CORE_PATH],
        "request_schema_blob_sha": expected[REQUEST_SCHEMA_PATH],
        "pack_schema_blob_sha": expected[PACK_SCHEMA_PATH],
        "serialization_profile": "hwm-canonical-json/v1",
    }
    return compiler, provenance


def validate_stage_schema(raw: Any, control_root: Path) -> dict[str, Any]:
    try:
        stage_schema = json.loads((control_root / STAGE_REQUEST_SCHEMA_PATH).read_text(encoding="utf-8"))
        source_schema = json.loads((control_root / REQUEST_SCHEMA_PATH).read_text(encoding="utf-8"))
        resource = Resource.from_contents(source_schema)
        registry = Registry().with_resource(source_schema["$id"], resource)
        Draft202012Validator(stage_schema, registry=registry).validate(raw)
    except Exception as exc:
        raise Reject("INVALID_SCHEMA", "stage request does not validate against the closed v1 schema") from exc
    if not isinstance(raw, dict):
        raise Reject("INVALID_SCHEMA", "stage request must be one object")
    return raw


def validate_stage_semantics(request: dict[str, Any], compiler: Any) -> None:
    source = request["source_request"]
    try:
        compiler.validate_request(source)
    except Exception as exc:
        raise Reject("INVALID_SCHEMA", "embedded task-context request is not canonical v1") from exc

    if request["repository"] != REPOSITORY or request["transport_issue"] != TRANSPORT_ISSUE:
        raise Reject("INVALID_TRANSPORT", "stage request is not bound to the exact repository transport")
    if source["product"].get("head_policy") != "must_equal_current":
        raise Reject("INVALID_SCHEMA", "staging requires product head_policy must_equal_current")
    if (
        request["expected_control_main"] != source["freshness"]["control_main_sha"]
        or request["expected_control_main"] != source["project_state"]["commit"]
        or request["expected_context_main"] != source["freshness"]["context_main_sha"]
        or request["expected_context_main"] != source["historical_ledger"]["commit"]
        or request["expected_product_main"] != source["product"]["commit"]
        or request["expected_product_main"] != source["product"]["expected_current_head"]
    ):
        raise Reject("INVALID_SCHEMA", "stage head bindings disagree with embedded source request")
    if request["compiler"]["commit"] != request["expected_control_main"]:
        raise Reject("TRUSTED_CODE_MISMATCH", "compiler commit does not equal expected protected control main")
    if request["compiler"]["max_blob_bytes"] != MAX_BLOB_BYTES:
        raise Reject("INVALID_SCHEMA", "stage request MAX_BLOB_BYTES differs from unchanged publisher boundary")
    if request["expectations"]["source_request_id"] != source["request_id"]:
        raise Reject("SOURCE_REQUEST_ID_MISMATCH", "expected source request id differs from embedded canonical request")
    digest = compiler.request_digest(source)
    if request["expectations"]["source_request_sha256"] != digest:
        raise Reject("SOURCE_REQUEST_SHA_MISMATCH", "expected canonical source-request SHA-256 mismatch")


def _comment_json(comment: Mapping[str, Any]) -> dict[str, Any] | None:
    body = comment.get("body")
    if not isinstance(body, str):
        return None
    try:
        value = json.loads(body)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def find_prior(reader: PublicGitHubReader, request: dict[str, Any], request_fingerprint: str, current_comment_id: int) -> dict[str, Any] | None:
    successes: list[dict[str, Any]] = []
    for comment in reader.comments():
        obj = _comment_json(comment)
        if not obj or obj.get("request_id") != request["request_id"] or comment.get("id") == current_comment_id:
            continue
        user = comment.get("user") or {}
        if obj.get("schema") == STAGE_REQUEST_SCHEMA and user.get("login") == ALLOWED_AUTHOR["login"] and user.get("id") == ALLOWED_AUTHOR["id"]:
            if fingerprint(obj) != request_fingerprint:
                raise Reject("REQUEST_ID_REUSE", "stage request id was previously used with a different normalized payload")
        if obj.get("schema") == STAGE_RESULT_SCHEMA and user.get("login") == RESULT_AUTHOR["login"] and user.get("id") == RESULT_AUTHOR["id"]:
            if obj.get("request_fingerprint") != request_fingerprint:
                raise Reject("REQUEST_ID_REUSE", "stage request id already has trusted result for a different normalized payload")
            if obj.get("status") == "success":
                successes.append(obj)
    if not successes:
        return None
    first = successes[0]
    for other in successes[1:]:
        for key in ("observations", "source_request", "compiler", "artifact"):
            if other.get(key) != first.get(key):
                raise Reject("REQUEST_ID_REUSE", "trusted successful stage results disagree on immutable provenance")
    return copy.deepcopy(first)


def _transport(event: Mapping[str, Any], workflow_run_id: int) -> dict[str, Any]:
    comment = event.get("comment") or {}
    return {
        "request_comment_id": int(comment["id"]),
        "result_author_login": RESULT_AUTHOR["login"],
        "result_author_id": RESULT_AUTHOR["id"],
        "workflow_repository": REPOSITORY,
        "workflow_run_id": int(workflow_run_id),
        "event_name": "issue_comment",
    }


def error_result(request_id: str, request_fingerprint: str, event: Mapping[str, Any], workflow_run_id: int, exc: Reject) -> dict[str, Any]:
    return {
        "schema": STAGE_RESULT_SCHEMA,
        "request_id": request_id,
        "status": "error",
        "request_fingerprint": request_fingerprint,
        "repository": REPOSITORY,
        "transport_issue": TRANSPORT_ISSUE,
        "observations": None,
        "source_request": None,
        "compiler": None,
        "artifact": None,
        "idempotent_replay": False,
        "error": {"code": exc.code, "message": exc.message, "retryable": exc.retryable},
        "transport": _transport(event, workflow_run_id),
    }


def stage_once(
    request: dict[str, Any],
    *,
    compiler: Any,
    compiler_provenance: dict[str, Any],
    reader_factory: Any,
    request_fingerprint: str,
    event: Mapping[str, Any],
    workflow_run_id: int,
) -> tuple[bytes, dict[str, Any]]:
    validate_stage_semantics(request, compiler)

    observed_control = reader_factory().observe_head(CONTROL_REPOSITORY)
    observed_context = reader_factory().observe_head(REPOSITORY)
    observed_product = reader_factory().observe_head(PRODUCT_REPOSITORY)
    if observed_control != request["expected_control_main"]:
        raise Reject("STALE_CONTROL_HEAD", "protected hwm-control/main differs from stage expectation")
    if observed_context != request["expected_context_main"]:
        raise Reject("STALE_CONTEXT_HEAD", "protected hwm-context/main differs from stage expectation")
    if observed_product != request["expected_product_main"]:
        raise Reject("STALE_PRODUCT_HEAD", "product main differs from must_equal_current stage expectation")

    provider1 = CompilerProvider(reader_factory(), compiler)
    provider2 = CompilerProvider(reader_factory(), compiler)
    try:
        first = compiler.compile_task_context(copy.deepcopy(request["source_request"]), provider1)
        second = compiler.compile_task_context(copy.deepcopy(request["source_request"]), provider2)
    except Reject:
        raise
    except Exception as exc:
        raise Reject("COMPILATION_REJECTED", str(exc) or "trusted deterministic compilation rejected exact inputs") from exc

    data1 = first.context_json
    data2 = second.context_json
    if data1 != data2:
        raise Reject("DOUBLE_COMPILE_MISMATCH", "two trusted compilations from identical exact inputs were not byte-identical")
    if len(data1) > MAX_BLOB_BYTES:
        raise Reject("PACK_TOO_LARGE", "canonical task-context pack exceeds unchanged publisher MAX_BLOB_BYTES")
    if not data1 or not data1.endswith(b"\n") or data1.endswith(b"\n\n") or data1.startswith(b"\xef\xbb\xbf"):
        raise Reject("COMPILATION_REJECTED", "compiled context bytes violate canonical serialization envelope")
    try:
        validate_pack_bytes(data1)
    except Exception as exc:
        raise Reject("COMPILATION_REJECTED", str(exc) or "compiled pack failed independent publisher validation") from exc

    context_digest = sha256(data1)
    blob_digest = git_blob_sha(data1)
    if request["expectations"]["context_sha256"] != context_digest:
        raise Reject("EXPECTED_CONTEXT_MISMATCH", "compiled canonical context SHA-256 differs from stage expectation")
    if request["expectations"]["git_blob_sha"] != blob_digest:
        raise Reject("EXPECTED_BLOB_MISMATCH", "compiled canonical Git blob SHA differs from stage expectation")

    source = request["source_request"]
    observations = {
        "control_main": observed_control,
        "context_main": observed_context,
        "product_main": observed_product,
        "issue_snapshot_sha256": source["issue_snapshot"]["snapshot_sha256"],
        "project_state": {
            "repository": source["project_state"]["repository"],
            "commit": source["project_state"]["commit"],
            "path": source["project_state"]["path"],
            "blob_sha": source["project_state"]["blob_sha"],
            "content_sha256": source["project_state"]["content_sha256"],
        },
        "historical_ledger": {
            "commit": source["historical_ledger"]["commit"],
            "claims": {
                "repository": source["historical_ledger"]["repository"],
                "commit": source["historical_ledger"]["commit"],
                "path": source["historical_ledger"]["claims"]["path"],
                "blob_sha": source["historical_ledger"]["claims"]["blob_sha"],
                "content_sha256": source["historical_ledger"]["claims"]["content_sha256"],
            },
            "conflicts": {
                "repository": source["historical_ledger"]["repository"],
                "commit": source["historical_ledger"]["commit"],
                "path": source["historical_ledger"]["conflicts"]["path"],
                "blob_sha": source["historical_ledger"]["conflicts"]["blob_sha"],
                "content_sha256": source["historical_ledger"]["conflicts"]["content_sha256"],
            },
        },
        "knowledge_deltas": [
            {
                "task_key": item["task_key"],
                "commit": item["commit"],
                "path": item["path"],
                "blob_sha": item["blob_sha"],
                "content_sha256": item["content_sha256"],
            }
            for item in source["knowledge_deltas"]["inputs"]
        ],
    }
    result_draft = {
        "schema": STAGE_RESULT_SCHEMA,
        "request_id": request["request_id"],
        "status": "success",
        "request_fingerprint": request_fingerprint,
        "repository": REPOSITORY,
        "transport_issue": TRANSPORT_ISSUE,
        "observations": observations,
        "source_request": {
            "request_id": source["request_id"],
            "request_sha256": compiler.request_digest(source),
        },
        "compiler": {
            **compiler_provenance,
            "compile_pass_count": 2,
            "byte_equal": True,
        },
        "artifact": None,
        "idempotent_replay": False,
        "error": None,
        "transport": _transport(event, workflow_run_id),
    }
    intent = {
        "action": "stage",
        "expected_context_sha256": context_digest,
        "expected_git_blob_sha": blob_digest,
        "expected_byte_length": len(data1),
        "result_draft": result_draft,
    }
    return data1, intent


def preflight(event: Mapping[str, Any], reader: PublicGitHubReader | None = None) -> dict[str, str]:
    reader = reader or PublicGitHubReader()
    issue = event.get("issue") or {}
    comment = event.get("comment") or {}
    repository = event.get("repository") or {}
    author = comment.get("user") or {}
    should = (
        issue.get("number") == TRANSPORT_ISSUE
        and not issue.get("pull_request")
        and repository.get("full_name") == REPOSITORY
        and author.get("login") == ALLOWED_AUTHOR["login"]
        and author.get("id") == ALLOWED_AUTHOR["id"]
    )
    raw: Any = None
    if should:
        try:
            raw = json.loads(comment.get("body", ""))
        except json.JSONDecodeError:
            should = False
        should = should and isinstance(raw, dict) and raw.get("schema") == STAGE_REQUEST_SCHEMA and isinstance(raw.get("request_id"), str) and REQUEST_ID_RE.fullmatch(raw["request_id"]) is not None
    if not should:
        return {"should_run": "false", "concurrency_key": "ignored", "control_sha": "", "context_sha": ""}

    context_sha = reader.observe_head(REPOSITORY)
    control_sha = reader.observe_head(CONTROL_REPOSITORY)
    workflow_sha = os.environ.get("GITHUB_SHA")
    if workflow_sha and workflow_sha != context_sha:
        return {"should_run": "false", "concurrency_key": raw["request_id"], "control_sha": "", "context_sha": ""}
    return {
        "should_run": "true",
        "concurrency_key": raw["request_id"],
        "control_sha": control_sha,
        "context_sha": context_sha,
    }


def prepare(event: Mapping[str, Any], control_root: Path, output_dir: Path, workflow_run_id: int, reader: PublicGitHubReader | None = None) -> dict[str, Any]:
    reader = reader or PublicGitHubReader()
    comment = event.get("comment") or {}
    raw = json.loads(comment.get("body", ""))
    request_id = raw.get("request_id") if isinstance(raw, dict) and isinstance(raw.get("request_id"), str) and REQUEST_ID_RE.fullmatch(raw["request_id"]) else "tcs1-" + "0" * 64
    request_fingerprint = fingerprint(raw) if isinstance(raw, dict) else "0" * 64
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        request = validate_stage_schema(raw, control_root)
        request_fingerprint = fingerprint(request)
        compiler, compiler_provenance = load_trusted_compiler(control_root, request)
        validate_stage_semantics(request, compiler)
        prior = find_prior(reader, request, request_fingerprint, int(comment["id"]))
        if prior is not None:
            replay = copy.deepcopy(prior)
            replay["idempotent_replay"] = True
            intent = {"action": "replay", "result": replay}
            (output_dir / "intent.json").write_text(canonical_json(intent) + "\n", encoding="utf-8")
            return intent
        data, intent = stage_once(
            request,
            compiler=compiler,
            compiler_provenance=compiler_provenance,
            reader_factory=PublicGitHubReader if reader.__class__ is PublicGitHubReader else (lambda: reader),
            request_fingerprint=request_fingerprint,
            event=event,
            workflow_run_id=workflow_run_id,
        )
        (output_dir / "context.json").write_bytes(data)
    except Reject as exc:
        result = error_result(request_id, request_fingerprint, event, workflow_run_id, exc)
        intent = {"action": "result_only", "result": result}
    except Exception as exc:
        wrapped = Reject("INTERNAL_ERROR", str(exc) or "trusted stage preparation failed", retryable=True)
        result = error_result(request_id, request_fingerprint, event, workflow_run_id, wrapped)
        intent = {"action": "result_only", "result": result}
    (output_dir / "intent.json").write_text(canonical_json(intent) + "\n", encoding="utf-8")
    return intent


def _write_outputs(path: Path, values: Mapping[str, str]) -> None:
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            handle.write(f"{key}={value}\n")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: task_context_stager.py preflight EVENT OUTPUT | prepare EVENT CONTROL_ROOT OUTPUT_DIR RUN_ID", file=sys.stderr)
        return 2
    event = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    if argv[1] == "preflight":
        if len(argv) != 4:
            return 2
        _write_outputs(Path(argv[3]), preflight(event))
        return 0
    if argv[1] == "prepare":
        if len(argv) != 6:
            return 2
        prepare(event, Path(argv[3]), Path(argv[4]), int(argv[5]))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
