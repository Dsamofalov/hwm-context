import copy
import json
import unittest

from publisher.task_context_contract import (
    ALLOWED_AUTHOR,
    CI_WORKFLOW,
    ISSUE_REPOSITORY,
    PACK_SCHEMA,
    REPOSITORY,
    REQUEST_SCHEMA,
    REQUIRED_CHECK,
    REQUIRED_INTEGRATION_ID,
    RESULT_AUTHOR,
    RESULT_SCHEMA,
    SERIALIZATION,
    TRANSPORT_ISSUE,
    Reject,
    canonical_json,
    fingerprint,
    git_blob_sha,
    sha256,
    validate_pack_bytes,
    validate_request,
    validate_result,
)
from publisher.task_context_publisher import preflight


def pack(task_key="I09-0047", issue_number=47, request_id="tcr1-" + "a" * 64):
    value = {
        "schema": PACK_SCHEMA,
        "request_binding": {"request_id": request_id, "request_sha256": "b" * 64},
        "task": {"task_key": task_key, "issue_repository": ISSUE_REPOSITORY, "issue_number": issue_number},
        "issue_snapshot": {"repository": ISSUE_REPOSITORY, "issue_number": issue_number},
        "product": {},
        "project_state": {},
        "historical_ledger": {},
        "knowledge_deltas": {},
        "authority_model": {
            "classes": [],
            "current_state_is_authoritative": True,
            "historical_is_not_current_state": True,
            "derived_context_is_not_authority": True,
            "llm_is_not_deterministic_authority": True,
        },
        "selection": {},
        "freshness": {
            "policy": "hwm-exact-bound-freshness/v1",
            "status": "fresh",
            "checks": [{"source_id": "fixture", "expected": "same", "observed": "same", "status": "match"}],
            "on_mismatch": "reject",
            "no_implicit_head_substitution": True,
        },
        "sources": [],
        "public_data": {
            "policy": "hwm-public-data/v1",
            "classification": "public-disclosure-safe",
            "on_violation": "reject",
        },
        "serialization": copy.deepcopy(SERIALIZATION),
    }
    return canonical_json(value).encode("utf-8") + b"\n"


def request(data=None, task_key="I09-0047", issue_number=47):
    data = data or pack(task_key, issue_number)
    source = json.loads(data)
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": "i09-0047-disposable-acceptance-v1",
        "repository": REPOSITORY,
        "transport_issue": TRANSPORT_ISSUE,
        "expected_base": "1" * 40,
        "publication_branch": f"publisher/task-context/{task_key.lower()}/disposable-acceptance-v1",
        "task": {
            "task_key": task_key,
            "issue_repository": ISSUE_REPOSITORY,
            "issue_number": issue_number,
            "source_request_id": source["request_binding"]["request_id"],
            "source_request_sha256": source["request_binding"]["request_sha256"],
        },
        "artifact": {
            "op": "add",
            "path": f"tasks/{task_key}/context.json",
            "blob_sha": git_blob_sha(data),
            "content_sha256": sha256(data),
            "mode": "100644",
            "pack_schema": PACK_SCHEMA,
        },
        "candidate": {
            "parent_sha": "1" * 40,
            "parent_count": 1,
            "tree_policy": "base-plus-exact-task-context-blob",
        },
        "ci": {
            "workflow": CI_WORKFLOW,
            "required_check": REQUIRED_CHECK,
            "status_integration_id": REQUIRED_INTEGRATION_ID,
        },
    }


class TaskContextPublisherContractTests(unittest.TestCase):
    def test_valid_request_pack_and_result(self):
        data = pack()
        req = request(data)
        validate_request(req)
        self.assertEqual(validate_pack_bytes(data, req)["task"]["task_key"], "I09-0047")
        result = {
            "schema": RESULT_SCHEMA,
            "request_id": req["request_id"],
            "status": "success",
            "repository": REPOSITORY,
            "transport_issue": TRANSPORT_ISSUE,
            "expected_base": req["expected_base"],
            "publication_branch": req["publication_branch"],
            "task": req["task"],
            "artifact": req["artifact"],
            "request_fingerprint": fingerprint(req),
            "idempotent_replay": False,
            "candidate": {"commit_sha": "2" * 40, "tree_sha": "3" * 40, "parent_sha": "1" * 40, "parent_count": 1},
            "pr": {"number": 9, "base_ref": "main", "head_ref": req["publication_branch"], "head_sha": "2" * 40},
            "ci_dispatch": {"workflow": CI_WORKFLOW, "run_id": 10, "head_sha": "2" * 40, "required_check": REQUIRED_CHECK},
            "required_status": {
                "context": REQUIRED_CHECK,
                "integration_id": REQUIRED_INTEGRATION_ID,
                "creator_login": RESULT_AUTHOR["login"],
                "creator_id": RESULT_AUTHOR["id"],
            },
            "error": None,
        }
        validate_result(result)

    def test_task_path_issue_context_markdown_and_modes_fail_closed(self):
        mutations = {
            "task": lambda r: r["task"].update(task_key="I09-0048"),
            "issue": lambda r: r["task"].update(issue_number=48),
            "path": lambda r: r["artifact"].update(path="tasks/I09-0048/context.json"),
            "context_md": lambda r: r["artifact"].update(path="tasks/I09-0047/context.md"),
            "executable": lambda r: r["artifact"].update(mode="100755"),
            "generic": lambda r: r["artifact"].update(path="tasks/anything/context.json"),
        }
        for name, mutate in mutations.items():
            req = request()
            mutate(req)
            with self.subTest(name=name), self.assertRaises(Reject):
                validate_request(req)

    def test_closed_fields_source_binding_and_candidate_semantics_fail_closed(self):
        req = request()
        req["extra"] = True
        with self.assertRaises(Reject):
            validate_request(req)
        req = request()
        req["task"]["source_request_id"] = "tcr1-" + "c" * 64
        with self.assertRaises(Reject):
            validate_pack_bytes(pack(), req)
        req = request()
        req["candidate"]["parent_count"] = 2
        with self.assertRaises(Reject):
            validate_request(req)

    def test_public_data_canonical_json_and_context_markdown_fail_closed(self):
        value = json.loads(pack())
        value["sources"] = [{"content": "api_key=abcdefghijklmnop"}]
        with self.assertRaises(Reject):
            validate_pack_bytes(canonical_json(value).encode("utf-8") + b"\n")
        with self.assertRaises(Reject):
            validate_pack_bytes(b'{"z":1, "a":2}\n')
        value = json.loads(pack())
        value["serialization"]["context_markdown"] = "generated"
        with self.assertRaises(Reject):
            validate_pack_bytes(canonical_json(value).encode("utf-8") + b"\n")

    def test_preflight_requires_exact_transport_and_author(self):
        req = request()
        event = {
            "repository": {"full_name": REPOSITORY},
            "issue": {"number": TRANSPORT_ISSUE},
            "comment": {"user": copy.deepcopy(ALLOWED_AUTHOR), "body": canonical_json(req)},
        }
        self.assertEqual(preflight(event)["should_run"], "true")
        event["comment"]["user"] = {"login": "mallory", "id": 1}
        self.assertEqual(preflight(event)["should_run"], "false")
        event["comment"]["user"] = copy.deepcopy(ALLOWED_AUTHOR)
        event["issue"]["number"] = 2
        self.assertEqual(preflight(event)["should_run"], "false")


if __name__ == "__main__":
    unittest.main()
