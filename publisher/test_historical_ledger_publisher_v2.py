import unittest

from publisher.historical_ledger_publisher_v2 import TransactionalPublisher, classify_pr_error


class FakeApi:
    def __init__(self):
        self.calls = []

    def request(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        return None


class TransactionalPublisherTests(unittest.TestCase):
    def test_actions_pr_permission_failure_is_specific_and_public_safe(self):
        reject = classify_pr_error(RuntimeError(
            "GitHub API POST /pulls failed with 403: GitHub Actions is not permitted to create or approve pull requests."
        ))
        self.assertEqual(reject.code, "PR_CREATION_FORBIDDEN")
        self.assertNotIn("bearer", reject.message.lower())
        self.assertNotIn("ghp_", reject.message.lower())

    def test_other_pr_failure_is_sanitized(self):
        reject = classify_pr_error(RuntimeError("GitHub API POST /pulls failed with 422: details"))
        self.assertEqual(reject.code, "PR_CREATION_FAILED")
        self.assertEqual(reject.message, "scoped publication PR creation failed")

    def test_compensation_deletes_only_scoped_ref(self):
        api = FakeApi()
        publisher = TransactionalPublisher(api)
        publisher._delete_scoped_ref("publisher/historical-ledger/i08-0037-test")
        publisher._delete_scoped_ref("main")
        self.assertEqual(
            api.calls,
            [("DELETE", "/git/refs/heads/publisher/historical-ledger/i08-0037-test", None)],
        )


if __name__ == "__main__":
    unittest.main()
