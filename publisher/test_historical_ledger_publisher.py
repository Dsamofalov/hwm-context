import json
import unittest
from publisher.historical_ledger_publisher import (
    ALLOWED_PATHS,
    REQUEST_SCHEMA,
    REPOSITORY,
    TRANSPORT_ISSUE,
    Reject,
    canonical_json,
    fingerprint,
    git_blob_sha,
    preflight,
    validate_public_blob,
    validate_request,
)


def request():
    claims = b""
    conflicts = b'{"schema":"hwm-historical-conflicts/v1","conflicts":[]}\n'
    return {
        "schema": REQUEST_SCHEMA,
        "request_id": "I08-0037-live-acceptance",
        "repository": REPOSITORY,
        "transport_issue": TRANSPORT_ISSUE,
        "expected_base": "8" * 40,
        "publication_branch": "publisher/historical-ledger/i08-0037-live-acceptance",
        "changes": [
            {"op": "add", "path": ALLOWED_PATHS[0], "blob_sha": git_blob_sha(claims), "mode": "100644"},
            {"op": "add", "path": ALLOWED_PATHS[1], "blob_sha": git_blob_sha(conflicts), "mode": "100644"},
        ],
        "ci": {"workflow": "repository-bootstrap-ci.yml", "required_check": "bootstrap"},
    }


class HistoricalLedgerPublisherSecurityTests(unittest.TestCase):
    def test_valid_exact_two_path_request(self):
        self.assertEqual(validate_request(request())["repository"], REPOSITORY)

    def test_fingerprint_is_deterministic(self):
        value = request()
        self.assertEqual(fingerprint(value), fingerprint(json.loads(canonical_json(value))))

    def test_bootstrap_v1_is_rejected(self):
        value = request()
        value["schema"] = "hwm-publish-request/bootstrap-v1"
        with self.assertRaises(Reject):
            validate_request(value)

    def test_wrong_repository_is_rejected(self):
        value = request()
        value["repository"] = "Dsamofalov/hwm-control"
        with self.assertRaises(Reject):
            validate_request(value)

    def test_forbidden_workflow_path_is_rejected(self):
        value = request()
        value["changes"][0]["path"] = ".github/workflows/pwn.yml"
        with self.assertRaises(Reject):
            validate_request(value)

    def test_protected_main_target_is_rejected(self):
        value = request()
        value["publication_branch"] = "main"
        with self.assertRaises(Reject):
            validate_request(value)

    def test_malformed_blob_sha_is_rejected(self):
        value = request()
        value["changes"][0]["blob_sha"] = "BAD"
        with self.assertRaises(Reject):
            validate_request(value)

    def test_unsafe_or_unbounded_candidate_is_rejected(self):
        with self.assertRaises(Reject):
            validate_public_blob(b"github_pat_secret")
        with self.assertRaises(Reject):
            validate_public_blob(b"x" * (1024 * 1024 + 1))

    def test_unauthorized_author_does_not_enter_privileged_job(self):
        event = {
            "repository": {"full_name": REPOSITORY},
            "issue": {"number": TRANSPORT_ISSUE},
            "comment": {"user": {"login": "Dsamofalov", "id": 25666939}, "body": canonical_json(request())},
        }
        self.assertEqual(preflight(event)["should_run"], "true")
        event["comment"]["user"] = {"login": "mallory", "id": 1}
        self.assertEqual(preflight(event)["should_run"], "false")


if __name__ == "__main__":
    unittest.main()
