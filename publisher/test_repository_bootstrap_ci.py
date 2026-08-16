from pathlib import Path
import fnmatch
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_WORKFLOW = ROOT / ".github" / "workflows" / "repository-bootstrap-ci.yml"
PUBLISHER_WORKFLOW = ROOT / ".github" / "workflows" / "historical-ledger-publisher.yml"
TASK_PUBLISHER_WORKFLOW = ROOT / ".github" / "workflows" / "task-context-publisher.yml"
CANONICAL_HISTORICAL_PATHS = (
    "claims/claims.jsonl",
    "claims/conflicts.json",
)
CANONICAL_TASK_PATTERN = "tasks/I[0-9][0-9]-[0-9][0-9][0-9][0-9]/context.json"
CHECKOUT_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def event_block(text, event, next_event):
    start = text.index(f"  {event}:\n")
    end = text.index(f"  {next_event}:\n", start)
    return text[start:end]


def ignored_by_generated_filter(paths):
    return bool(paths) and all(
        path in CANONICAL_HISTORICAL_PATHS or fnmatch.fnmatchcase(path, CANONICAL_TASK_PATTERN)
        for path in paths
    )


class RepositoryBootstrapAutomationCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bootstrap = BOOTSTRAP_WORKFLOW.read_text(encoding="utf-8")
        cls.publisher = PUBLISHER_WORKFLOW.read_text(encoding="utf-8")
        cls.task_publisher = TASK_PUBLISHER_WORKFLOW.read_text(encoding="utf-8")
        cls.pr_block = event_block(cls.bootstrap, "pull_request", "push")

    def test_pull_request_trigger_preserved_with_exact_generated_ignores(self):
        self.assertIn("    branches: [main]\n", self.pr_block)
        self.assertIn("    paths-ignore:\n", self.pr_block)
        ignored = [
            line.strip()[2:]
            for line in self.pr_block.splitlines()
            if line.strip().startswith("- ")
        ]
        self.assertEqual(ignored, [*CANONICAL_HISTORICAL_PATHS, CANONICAL_TASK_PATTERN])

    def test_generated_filter_is_exact_not_broad(self):
        self.assertNotIn("claims/**", self.pr_block)
        self.assertNotIn("claims/*", self.pr_block)
        self.assertNotIn("tasks/**", self.pr_block)
        self.assertNotIn("tasks/*/context.json", self.pr_block)
        self.assertTrue(ignored_by_generated_filter(CANONICAL_HISTORICAL_PATHS))
        self.assertTrue(ignored_by_generated_filter(("tasks/I09-0047/context.json",)))
        self.assertFalse(ignored_by_generated_filter(("claims/claims.jsonl", "README.md")))
        self.assertFalse(ignored_by_generated_filter(("claims/wrong.json",)))
        self.assertFalse(ignored_by_generated_filter(("tasks/I09-0047/context.md",)))
        self.assertFalse(ignored_by_generated_filter(("tasks/not-a-task/context.json",)))
        self.assertFalse(ignored_by_generated_filter(("tasks/I09-0047/context.json", "README.md")))

    def test_no_generated_pr_automatic_target_gate(self):
        self.assertNotIn("  pull_request_target:\n", self.bootstrap)
        self.assertNotIn("checks: write", self.bootstrap)
        self.assertNotIn("statuses: write", self.bootstrap)
        self.assertNotIn("strict_generated_pr_gate", self.bootstrap)
        self.assertNotIn("task_context_strict_gate", self.bootstrap)

    def test_push_main_and_workflow_dispatch_preserved(self):
        self.assertIn("  push:\n    branches: [main]\n", self.bootstrap)
        self.assertIn("  workflow_dispatch:\n", self.bootstrap)

    def test_dispatch_exact_head_verification_preserved(self):
        self.assertIn("description: exact candidate commit SHA to validate", self.bootstrap)
        self.assertIn('test "$GITHUB_SHA" = "$EXPECTED_HEAD"', self.bootstrap)
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.expected_head", self.bootstrap)
        self.assertIn('run: test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD"', self.bootstrap)

    def test_required_bootstrap_name_and_checkout_pin_preserved(self):
        self.assertIn("jobs:\n  bootstrap:\n    name: bootstrap\n", self.bootstrap)
        self.assertIn(CHECKOUT_PIN, self.bootstrap)
        self.assertNotIn("actions/checkout@main", self.bootstrap)
        self.assertNotIn("actions/checkout@master", self.bootstrap)

    def test_task_validation_is_repository_local_and_fail_closed(self):
        self.assertIn("python -m publisher.task_context_validation .", self.bootstrap)
        self.assertIn("test -f tasks/.gitkeep", self.bootstrap)
        self.assertNotIn("for d in bootstrap state tasks wiki graph health", self.bootstrap)

    def test_historical_publisher_security_boundary_remains_repository_scoped(self):
        self.assertIn("HWM_CONTEXT_PUBLISHER_TOKEN: ${{ github.token }}", self.publisher)
        self.assertIn("ref: main", self.publisher)
        self.assertIn("persist-credentials: false", self.publisher)
        self.assertIn(CHECKOUT_PIN, self.publisher)
        self.assertIn("run: python -m publisher.historical_ledger_publisher_v2 publish", self.publisher)
        publish_block = self.publisher[
            self.publisher.index("  publish:\n"):self.publisher.index("  strict_gate:\n")
        ]
        for permission in ("contents: write", "pull-requests: write", "issues: write", "actions: write"):
            self.assertIn(permission, publish_block)
        self.assertNotIn("checks: write", publish_block)
        self.assertNotIn("statuses: write", publish_block)
        self.assertNotIn("gh pr merge", self.publisher)
        self.assertNotIn("pull_request_review", self.publisher)

    def test_historical_strict_gate_is_isolated_read_plus_status_writer(self):
        strict_block = self.publisher[
            self.publisher.index("  strict_gate:\n"):self.publisher.index("  cleanup:\n")
        ]
        for permission in ("actions: read", "contents: read", "issues: read", "pull-requests: read", "statuses: write"):
            self.assertIn(permission, strict_block)
        for forbidden in ("checks: write", "contents: write", "pull-requests: write", "issues: write"):
            self.assertNotIn(forbidden, strict_block)
        self.assertIn("HWM_CONTEXT_STRICT_GATE_TOKEN: ${{ github.token }}", strict_block)
        self.assertIn("python -m publisher.strict_check_publisher", strict_block)
        self.assertIn("ref: main", strict_block)
        self.assertIn("persist-credentials: false", strict_block)

    def test_task_context_authorities_are_separate(self):
        publish_block = self.task_publisher[
            self.task_publisher.index("  publish:\n"):self.task_publisher.index("  strict_gate:\n")
        ]
        strict_block = self.task_publisher[
            self.task_publisher.index("  strict_gate:\n"):self.task_publisher.index("  cleanup:\n")
        ]
        self.assertIn("HWM_TASK_CONTEXT_PUBLISHER_TOKEN: ${{ github.token }}", publish_block)
        self.assertIn("python -m publisher.task_context_publisher publish", publish_block)
        for permission in ("contents: write", "pull-requests: write", "issues: write", "actions: write"):
            self.assertIn(permission, publish_block)
        self.assertNotIn("statuses: write", publish_block)
        for permission in ("actions: read", "contents: read", "issues: read", "pull-requests: read", "statuses: write"):
            self.assertIn(permission, strict_block)
        for forbidden in ("contents: write", "pull-requests: write", "issues: write"):
            self.assertNotIn(forbidden, strict_block)
        self.assertIn("HWM_TASK_CONTEXT_STRICT_GATE_TOKEN: ${{ github.token }}", strict_block)
        self.assertIn("python -m publisher.task_context_strict_gate", strict_block)
        self.assertIn("ref: main", strict_block)
        self.assertIn("persist-credentials: false", strict_block)
        self.assertIn(CHECKOUT_PIN, self.task_publisher)


if __name__ == "__main__":
    unittest.main()
