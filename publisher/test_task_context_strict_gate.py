import unittest

from publisher.task_context_contract import Reject
from publisher.task_context_strict_gate import validate_snapshot

BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40


def snapshot(**changes):
    first_pr = {
        "state": "open",
        "base": {"sha": BASE},
        "head": {"sha": HEAD},
        "merge_commit_sha": MERGE,
    }
    final_pr = {
        "state": "open",
        "base": {"sha": BASE},
        "head": {"sha": HEAD},
        "merge_commit_sha": MERGE,
    }
    value = {
        "expected_base": BASE,
        "first_main": BASE,
        "final_main": BASE,
        "first_branch_head": HEAD,
        "final_branch_head": HEAD,
        "first_pr": first_pr,
        "final_pr": final_pr,
        "expected_head": HEAD,
        "expected_merge": MERGE,
    }
    value.update(changes)
    return value


class StrictGateSnapshotTests(unittest.TestCase):
    def test_exact_snapshot_accepts(self):
        validate_snapshot(**snapshot())

    def test_base_head_merge_and_state_drift_reject(self):
        cases = [
            {"final_main": "d" * 40},
            {"final_branch_head": "d" * 40},
            {"final_pr": {"state": "open", "base": {"sha": BASE}, "head": {"sha": "d" * 40}, "merge_commit_sha": MERGE}},
            {"final_pr": {"state": "open", "base": {"sha": BASE}, "head": {"sha": HEAD}, "merge_commit_sha": "d" * 40}},
            {"final_pr": {"state": "closed", "base": {"sha": BASE}, "head": {"sha": HEAD}, "merge_commit_sha": MERGE}},
        ]
        for case in cases:
            with self.subTest(case=case), self.assertRaises(Reject):
                validate_snapshot(**snapshot(**case))


if __name__ == "__main__":
    unittest.main()
