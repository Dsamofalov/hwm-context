import copy
import types
import unittest
from unittest import mock

from publisher import task_context_stager as stager

C = "1" * 40
X = "2" * 40
P = "3" * 40
REQ_ID = "tcr1-" + "4" * 64
REQ_SHA = "5" * 64
CTX_SHA = "6" * 64
BLOB_SHA = "7" * 40


def source_request():
    return {
        "request_id": REQ_ID,
        "freshness": {"control_main_sha": C, "context_main_sha": X},
        "project_state": {
            "repository": stager.CONTROL_REPOSITORY,
            "commit": C,
            "path": "state/current.json",
            "blob_sha": "8" * 40,
            "content_sha256": "9" * 64,
        },
        "historical_ledger": {
            "repository": stager.REPOSITORY,
            "commit": X,
            "claims": {"path": "claims/claims.jsonl", "blob_sha": "a" * 40, "content_sha256": "b" * 64},
            "conflicts": {"path": "claims/conflicts.json", "blob_sha": "c" * 40, "content_sha256": "d" * 64},
        },
        "knowledge_deltas": {"inputs": [{
            "task_key": "I09-0047", "commit": C, "path": "knowledge-deltas/I09-0047.json",
            "blob_sha": "e" * 40, "content_sha256": "f" * 64,
        }]},
        "product": {
            "repository": stager.PRODUCT_REPOSITORY,
            "commit": P,
            "head_policy": "must_equal_current",
            "expected_current_head": P,
        },
        "issue_snapshot": {"snapshot_sha256": "0" * 64},
    }


def stage_request():
    source = source_request()
    return {
        "schema": stager.STAGE_REQUEST_SCHEMA,
        "request_id": "tcs1-" + "1" * 64,
        "repository": stager.REPOSITORY,
        "transport_issue": stager.TRANSPORT_ISSUE,
        "expected_control_main": C,
        "expected_context_main": X,
        "expected_product_main": P,
        "source_request": source,
        "expectations": {
            "source_request_id": REQ_ID,
            "source_request_sha256": REQ_SHA,
            "context_sha256": CTX_SHA,
            "git_blob_sha": BLOB_SHA,
        },
        "compiler": {
            "repository": stager.CONTROL_REPOSITORY,
            "commit": C,
            "max_blob_bytes": stager.MAX_BLOB_BYTES,
        },
    }


class FakeCompiler:
    class SourceFetchError(RuntimeError):
        def __init__(self, code, message, retryable=False):
            super().__init__(message)
            self.code, self.message, self.retryable = code, message, retryable

    class ExactBlob:
        def __init__(self, content, blob_sha=None):
            self.content, self.blob_sha = content, blob_sha

    def __init__(self, outputs=None, compile_error=None):
        self.outputs = list(outputs or [b"ok\n", b"ok\n"])
        self.compile_error = compile_error

    @staticmethod
    def validate_request(_request):
        return None

    @staticmethod
    def request_digest(_request):
        return REQ_SHA

    def compile_task_context(self, _request, _provider):
        if self.compile_error:
            raise self.compile_error
        return types.SimpleNamespace(context_json=self.outputs.pop(0))


class FakeReader:
    def __init__(self, heads=None, comments=None):
        self.heads = {stager.CONTROL_REPOSITORY: C, stager.REPOSITORY: X, stager.PRODUCT_REPOSITORY: P}
        if heads:
            self.heads.update(heads)
        self._comments = list(comments or [])

    def observe_head(self, repository):
        return self.heads[repository]

    def comments(self):
        return copy.deepcopy(self._comments)

    def fetch_issue_raw(self, repository, issue_number):
        return {}

    def fetch_blob_bytes(self, repository, commit, path):
        return b"x", stager.git_blob_sha(b"x")


class TaskContextStagerTests(unittest.TestCase):
    def test_unauthorized_transport_author_never_mints_stage_job(self):
        event = {
            "issue": {"number": 27},
            "repository": {"full_name": stager.REPOSITORY},
            "comment": {"body": '{"schema":"hwm-task-context-stage-request/v1","request_id":"tcs1-' + '1' * 64 + '"}', "user": {"login": "intruder", "id": 1}},
        }
        self.assertEqual(stager.preflight(event, FakeReader())["should_run"], "false")

    def test_wrong_repository_issue_and_schema_never_mint_stage_job(self):
        body = '{"schema":"hwm-task-context-stage-request/v1","request_id":"tcs1-' + '1' * 64 + '"}'
        base = {"issue": {"number": 27}, "repository": {"full_name": stager.REPOSITORY}, "comment": {"body": body, "user": stager.ALLOWED_AUTHOR}}
        for mutate in (
            lambda e: e["issue"].update(number=28),
            lambda e: e["repository"].update(full_name="Dsamofalov/other"),
            lambda e: e["comment"].update(body=body.replace("stage-request/v1", "stage-request/v2")),
        ):
            event = copy.deepcopy(base); mutate(event)
            self.assertEqual(stager.preflight(event, FakeReader())["should_run"], "false")

    def test_stage_semantics_reject_wrong_transport_source_identity_and_candidate_control(self):
        compiler = FakeCompiler()
        cases = []
        req = stage_request(); req["repository"] = "Dsamofalov/other"; cases.append((req, "INVALID_TRANSPORT"))
        req = stage_request(); req["expectations"]["source_request_id"] = "tcr1-" + "9" * 64; cases.append((req, "SOURCE_REQUEST_ID_MISMATCH"))
        req = stage_request(); req["expectations"]["source_request_sha256"] = "9" * 64; cases.append((req, "SOURCE_REQUEST_SHA_MISMATCH"))
        req = stage_request(); req["compiler"]["commit"] = "9" * 40; cases.append((req, "TRUSTED_CODE_MISMATCH"))
        req = stage_request(); req["source_request"]["product"]["head_policy"] = "exact_revision_only"; cases.append((req, "INVALID_SCHEMA"))
        for req, code in cases:
            with self.subTest(code=code), self.assertRaises(stager.Reject) as caught:
                stager.validate_stage_semantics(req, compiler)
            self.assertEqual(caught.exception.code, code)

    def test_stale_control_context_and_product_heads_fail_before_compilation(self):
        for repo, code in (
            (stager.CONTROL_REPOSITORY, "STALE_CONTROL_HEAD"),
            (stager.REPOSITORY, "STALE_CONTEXT_HEAD"),
            (stager.PRODUCT_REPOSITORY, "STALE_PRODUCT_HEAD"),
        ):
            compiler = FakeCompiler()
            reader = FakeReader({repo: "9" * 40})
            with self.subTest(repo=repo), self.assertRaises(stager.Reject) as caught:
                stager.stage_once(
                    stage_request(), compiler=compiler, compiler_provenance={}, reader_factory=lambda: reader,
                    request_fingerprint="a" * 64, event={"comment": {"id": 1}}, workflow_run_id=1,
                )
            self.assertEqual(caught.exception.code, code)
            self.assertEqual(len(compiler.outputs), 2)

    def test_double_compile_wrong_context_wrong_blob_and_oversize_fail_closed(self):
        base_data = b"canonical\n"
        cases = [
            ([base_data, b"different\n"], None, None, "DOUBLE_COMPILE_MISMATCH"),
            ([base_data, base_data], "0" * 64, stager.git_blob_sha(base_data), "EXPECTED_CONTEXT_MISMATCH"),
            ([base_data, base_data], stager.sha256(base_data), "0" * 40, "EXPECTED_BLOB_MISMATCH"),
            ([b"x" * (stager.MAX_BLOB_BYTES + 1)] * 2, None, None, "PACK_TOO_LARGE"),
        ]
        for outputs, expected_context, expected_blob, code in cases:
            req = stage_request()
            if expected_context is None:
                expected_context = stager.sha256(outputs[0])
            if expected_blob is None:
                expected_blob = stager.git_blob_sha(outputs[0])
            req["expectations"]["context_sha256"] = expected_context
            req["expectations"]["git_blob_sha"] = expected_blob
            compiler = FakeCompiler(outputs=outputs)
            with self.subTest(code=code), mock.patch.object(stager, "validate_pack_bytes", return_value={}):
                with self.assertRaises(stager.Reject) as caught:
                    stager.stage_once(req, compiler=compiler, compiler_provenance={}, reader_factory=FakeReader,
                                      request_fingerprint="a" * 64, event={"comment": {"id": 1}}, workflow_run_id=1)
            self.assertEqual(caught.exception.code, code)

    def test_compiler_public_data_or_source_rejection_is_fail_closed(self):
        compiler = FakeCompiler(compile_error=ValueError("public-data policy violation in issue.content"))
        with self.assertRaises(stager.Reject) as caught:
            stager.stage_once(stage_request(), compiler=compiler, compiler_provenance={}, reader_factory=FakeReader,
                              request_fingerprint="a" * 64, event={"comment": {"id": 1}}, workflow_run_id=1)
        self.assertEqual(caught.exception.code, "COMPILATION_REJECTED")
        self.assertIn("public-data", caught.exception.message)

    def test_request_id_reuse_with_changed_normalized_payload_fails_closed(self):
        request = stage_request()
        prior = copy.deepcopy(request)
        prior["expected_product_main"] = "9" * 40
        comments = [{"id": 2, "body": stager.canonical_json(prior), "user": stager.ALLOWED_AUTHOR}]
        reader = FakeReader(comments=comments)
        with self.assertRaises(stager.Reject) as caught:
            stager.find_prior(reader, request, stager.fingerprint(request), 1)
        self.assertEqual(caught.exception.code, "REQUEST_ID_REUSE")

    def test_exact_success_replay_is_immutable_and_requires_bot_result_authority(self):
        request = stage_request(); fp = stager.fingerprint(request)
        success = {
            "schema": stager.STAGE_RESULT_SCHEMA, "request_id": request["request_id"], "request_fingerprint": fp,
            "status": "success", "observations": {"x": 1}, "source_request": {"x": 2},
            "compiler": {"x": 3}, "artifact": {"x": 4},
        }
        ignored = {"id": 2, "body": stager.canonical_json(success), "user": {"login": "someone", "id": 2}}
        trusted = {"id": 3, "body": stager.canonical_json(success), "user": stager.RESULT_AUTHOR}
        replay = stager.find_prior(FakeReader(comments=[ignored, trusted]), request, fp, 1)
        self.assertEqual(replay, success)


if __name__ == "__main__":
    unittest.main()
