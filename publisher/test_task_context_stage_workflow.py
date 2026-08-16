import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "task-context-stager.yml"
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"


class TaskContextStageWorkflowTests(unittest.TestCase):
    def test_workflow_is_issue_transport_only_and_checkout_is_pinned(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("issue_comment:", text)
        self.assertNotIn("pull_request_target:", text)
        self.assertNotIn("workflow_dispatch:", text)
        self.assertGreaterEqual(text.count(f"actions/checkout@{CHECKOUT_SHA}"), 3)
        self.assertGreaterEqual(text.count("persist-credentials: false"), 3)

    def test_stage_job_has_only_required_write_permissions(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        stage = text.split("  stage:\n", 1)[1]
        permissions = stage.split("    steps:\n", 1)[0]
        self.assertIn("contents: write", permissions)
        self.assertIn("issues: write", permissions)
        for forbidden in (
            "pull-requests:",
            "actions:",
            "statuses:",
            "checks:",
            "workflows:",
        ):
            self.assertNotIn(forbidden, permissions)

    def test_preflight_has_pinned_schema_dependencies_before_importing_stager(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        preflight = text.split("  preflight:\n", 1)[1].split("\n  stage:\n", 1)[0]
        install = "python -m pip install --disable-pip-version-check 'jsonschema==4.23.0'"
        parse = "python -m publisher.task_context_stager preflight"
        self.assertIn(install, preflight)
        self.assertIn(parse, preflight)
        self.assertLess(preflight.index(install), preflight.index(parse))

    def test_token_is_exposed_only_to_confined_uploader_step(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(text.count("${{ github.token }}"), 1)
        self.assertEqual(text.count("HWM_TASK_CONTEXT_STAGE_TOKEN:"), 1)
        compile_block = text.split("Compile twice and prepare inert upload intent without token", 1)[1].split("Upload exact blob", 1)[0]
        self.assertNotIn("github.token", compile_block)
        self.assertNotIn("HWM_TASK_CONTEXT_STAGE_TOKEN", compile_block)
        upload_block = text.split("Upload exact blob and normalized result through confined endpoints", 1)[1]
        self.assertIn("HWM_TASK_CONTEXT_STAGE_TOKEN: ${{ github.token }}", upload_block)
        self.assertIn("publisher.task_context_stage_uploader upload", upload_block)

    def test_protected_exact_control_and_context_checkouts_are_verified(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("ref: ${{ needs.preflight.outputs.context_sha }}", text)
        self.assertIn("repository: Dsamofalov/hwm-control", text)
        self.assertIn("ref: ${{ needs.preflight.outputs.control_sha }}", text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$EXPECTED_CONTEXT_SHA"', text)
        self.assertIn('test "$(git -C trusted-control rev-parse HEAD)" = "$EXPECTED_CONTROL_SHA"', text)


if __name__ == "__main__":
    unittest.main()
