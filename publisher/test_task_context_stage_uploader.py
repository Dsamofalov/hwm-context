import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from publisher import task_context_stage_uploader as uploader

ROOT = Path(__file__).resolve().parents[1]
UPLOADER = ROOT / "publisher" / "task_context_stage_uploader.py"


class TaskContextStageUploaderTests(unittest.TestCase):
    def test_credentialed_source_has_only_exact_allowed_mutation_endpoints(self):
        source = UPLOADER.read_text(encoding="utf-8")
        self.assertIn('BLOB_POST_URL = "https://api.github.com/repos/Dsamofalov/hwm-context/git/blobs"', source)
        self.assertIn('RESULT_POST_URL = "https://api.github.com/repos/Dsamofalov/hwm-context/issues/27/comments"', source)
        self.assertNotIn("def request(", source)
        self.assertNotIn("repository: str", source)
        self.assertNotIn("method: str", source)
        self.assertNotIn("path: str", source)
        for forbidden in (
            "/git/refs",
            "/git/ref/",
            "/git/trees",
            "/git/commits",
            "/pulls",
            "/statuses",
            "/actions/",
            "/rulesets",
            "/releases",
            "/contents/",
            "workflow_dispatch",
        ):
            self.assertNotIn(forbidden, source)

    def test_repository_transport_and_post_methods_are_constants_not_intent_fields(self):
        source = UPLOADER.read_text(encoding="utf-8")
        self.assertEqual(uploader.REPOSITORY, "Dsamofalov/hwm-context")
        self.assertEqual(uploader.TRANSPORT_ISSUE, 27)
        self.assertIn('method="POST"', source)
        self.assertNotIn('intent["repository"]', source)
        self.assertNotIn('intent["path"]', source)
        self.assertNotIn('intent["method"]', source)

    def test_arbitrary_action_repository_path_or_method_injection_rejected_before_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for intent in (
                {"action": "delete_ref"},
                {"action": "stage", "repository": "evil/repo"},
                {"action": "stage", "path": "/git/refs", "method": "DELETE"},
            ):
                path = root / "intent.json"
                path.write_text(json.dumps(intent), encoding="utf-8")
                with self.subTest(intent=intent), mock.patch("urllib.request.urlopen") as urlopen:
                    with self.assertRaises(RuntimeError):
                        uploader.upload_intent(path)
                    urlopen.assert_not_called()

    def test_stage_intent_extra_request_controlled_surface_is_rejected_before_network(self):
        intent = {
            "action": "stage",
            "expected_context_sha256": "a" * 64,
            "expected_git_blob_sha": "b" * 40,
            "expected_byte_length": 1,
            "result_draft": {},
            "path": "/git/refs",
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intent.json"
            path.write_text(json.dumps(intent), encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                with self.assertRaisesRegex(RuntimeError, "fields are not closed"):
                    uploader.upload_intent(path)
                urlopen.assert_not_called()

    def test_replay_performs_no_credentialed_network_operation(self):
        result = {"schema": "hwm-task-context-stage-result/v1", "idempotent_replay": False}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "intent.json"
            path.write_text(json.dumps({"action": "replay", "result": result}), encoding="utf-8")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch("urllib.request.urlopen") as urlopen:
                replay = uploader.upload_intent(path)
            self.assertTrue(replay["idempotent_replay"])
            urlopen.assert_not_called()

    def test_blob_creation_and_result_comment_are_posts_to_constants(self):
        requests = []

        class Response:
            def __init__(self, body):
                self.body = body
            def __enter__(self):
                return self
            def __exit__(self, *args):
                return False
            def read(self):
                return json.dumps(self.body).encode()

        def fake_urlopen(request, timeout=30):
            requests.append((request.full_url, request.method))
            if request.full_url == uploader.BLOB_POST_URL:
                return Response({"sha": "a" * 40})
            if request.full_url == uploader.RESULT_POST_URL:
                return Response({"id": 123})
            raise AssertionError(request.full_url)

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            self.assertEqual(uploader._create_exact_blob("token", b"x"), "a" * 40)
            self.assertEqual(uploader._post_normalized_result("token", {"schema": "x"}), 123)
        self.assertEqual(requests, [(uploader.BLOB_POST_URL, "POST"), (uploader.RESULT_POST_URL, "POST")])


if __name__ == "__main__":
    unittest.main()
