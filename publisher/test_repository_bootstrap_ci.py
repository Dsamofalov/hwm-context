from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
BOOTSTRAP_WORKFLOW = ROOT / ".github" / "workflows" / "repository-bootstrap-ci.yml"
PUBLISHER_WORKFLOW = ROOT / ".github" / "workflows" / "historical-ledger-publisher.yml"
CANONICAL_GENERATED_PATHS = (
    "claims/claims.jsonl",
    "claims/conflicts.json",
)
CHECKOUT_PIN = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"


def event_block(text, event, next_event):
    start = text.index(f"  {event}:\n")
    end = text.index(f"  {next_event}:\n", start)
    return text[start:end]


def ignored_by_exact_generated_filter(paths):
    allowed = set(CANONICAL_GENERATED_PATHS)
    return bool(paths) and all(path in allowed for path in paths)


class RepositoryBootstrapAutomationCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bootstrap = BOOTSTRAP_WORKFLOW.read_text(encoding="utf-8")
        cls.publisher = PUBLISHER_WORKFLOW.read_text(encoding="utf-8")
        cls.pr_block = event_block(cls.bootstrap, "pull_request", "pull_request_target")
        cls.pr_target_block = event_block(cls.bootstrap, "pull_request_target", "push")

    def test_pull_request_trigger_preserved_with_exact_paths_ignore(self):
        self.assertIn("    branches: [main]\n", self.pr_block)
        self.assertIn("    paths-ignore:\n", self.pr_block)
        ignored = [
            line.strip()[2:]
            for line in self.pr_block.splitlines()
            if line.strip().startswith("- ")
        ]
        self.assertEqual(ignored, list(CANONICAL_GENERATED_PATHS))

    def test_generated_filter_is_exact_not_broad(self):
        self.assertNotIn("claims/**", self.pr_block)
        self.assertNotIn("claims/*", self.pr_block)
        self.assertTrue(ignored_by_exact_generated_filter(CANONICAL_GENERATED_PATHS))
        self.assertFalse(
            ignored_by_exact_generated_filter(
                ("claims/claims.jsonl", "README.md")
            )
        )
        self.assertFalse(
            ignored_by_exact_generated_filter(("claims/wrong.json",))
        )

    def test_pull_request_target_is_narrow_and_read_only(self):
        self.assertIn("    types: [opened, reopened, synchronize]\n", self.pr_target_block)
        self.assertIn("    branches: [main]\n", self.pr_target_block)
        self.assertIn("    paths:\n", self.pr_target_block)
        paths = [
            line.strip()[2:]
            for line in self.pr_target_block.splitlines()
            if line.strip().startswith("- ")
        ]
        self.assertEqual(paths, list(CANONICAL_GENERATED_PATHS))
        self.assertNotIn("claims/**", self.pr_target_block)
        self.assertIn("      actions: read\n", self.bootstrap)
        self.assertIn("      contents: read\n", self.bootstrap)
        self.assertIn("      issues: read\n", self.bootstrap)
        self.assertIn("      pull-requests: read\n", self.bootstrap)
        self.assertNotIn("checks: write", self.bootstrap)

    def test_pr_target_required_name_is_only_for_trusted_publisher_identity(self):
        self.assertIn("github.event.pull_request.user.login != 'github-actions[bot]'", self.bootstrap)
        self.assertIn("github.event.pull_request.user.id != 41898282", self.bootstrap)
        self.assertIn("!startsWith(github.event.pull_request.head.ref, 'publisher/historical-ledger/')", self.bootstrap)
        self.assertIn("'generated-ledger-preflight' || 'bootstrap'", self.bootstrap)
        self.assertIn("python -m publisher.strict_generated_pr_gate", self.bootstrap)
        self.assertIn("HWM_CONTEXT_GATE_TOKEN: ${{ github.token }}", self.bootstrap)

    def test_push_main_and_workflow_dispatch_preserved(self):
        self.assertIn("  push:\n    branches: [main]\n", self.bootstrap)
        self.assertIn("  workflow_dispatch:\n", self.bootstrap)

    def test_dispatch_exact_head_verification_preserved(self):
        self.assertIn("description: exact candidate commit SHA to validate", self.bootstrap)
        self.assertIn('test "$GITHUB_SHA" = "$EXPECTED_HEAD"', self.bootstrap)
        self.assertIn(
            "github.event_name == 'workflow_dispatch' && inputs.expected_head",
            self.bootstrap,
        )
        self.assertIn(
            'run: test "$(git rev-parse HEAD)" = "$EXPECTED_HEAD"',
            self.bootstrap,
        )

    def test_pr_target_checks_out_only_protected_base(self):
        self.assertIn(
            "github.event_name == 'pull_request_target' && github.event.pull_request.base.sha",
            self.bootstrap,
        )
        self.assertIn("Verify protected-base checkout for generated PR gate", self.bootstrap)
        self.assertIn('run: test "$(git rev-parse HEAD)" = "$EXPECTED_BASE"', self.bootstrap)

    def test_required_bootstrap_name_and_checkout_pin_preserved(self):
        self.assertIn("jobs:\n  bootstrap:\n", self.bootstrap)
        self.assertIn("'bootstrap' }}", self.bootstrap)
        self.assertIn(CHECKOUT_PIN, self.bootstrap)
        self.assertNotIn("actions/checkout@main", self.bootstrap)
        self.assertNotIn("actions/checkout@master", self.bootstrap)

    def test_publisher_security_boundary_remains_repository_scoped(self):
        self.assertIn("HWM_CONTEXT_PUBLISHER_TOKEN: ${{ github.token }}", self.publisher)
        self.assertIn("ref: main", self.publisher)
        self.assertIn("persist-credentials: false", self.publisher)
        self.assertIn(CHECKOUT_PIN, self.publisher)
        self.assertIn(
            "run: python -m publisher.historical_ledger_publisher_v2 publish",
            self.publisher,
        )
        self.assertNotIn("gh pr merge", self.publisher)
        self.assertNotIn("pull_request_review", self.publisher)


if __name__ == "__main__":
    unittest.main()
