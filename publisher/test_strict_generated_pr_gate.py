import unittest

from publisher.strict_generated_pr_gate import validate_strict_snapshot
from publisher.historical_ledger_publisher import Reject


BASE = "a" * 40
HEAD = "b" * 40
MERGE = "c" * 40
TREE = "d" * 40
PATHS = ["claims/claims.jsonl", "claims/conflicts.json"]


def valid(**overrides):
    values = dict(
        event_pr_number=16,
        first_pr_number=16,
        final_pr_number=16,
        expected_base=BASE,
        event_base=BASE,
        first_base=BASE,
        final_base=BASE,
        first_main=BASE,
        final_main=BASE,
        event_head=HEAD,
        first_head=HEAD,
        final_head=HEAD,
        first_merge=MERGE,
        final_merge=MERGE,
        changed_paths=PATHS,
        head_parents=[BASE],
        merge_parents=[BASE, HEAD],
        head_tree=TREE,
        merge_tree=TREE,
    )
    values.update(overrides)
    return values


class StrictGeneratedPrSnapshotTests(unittest.TestCase):
    def test_exact_snapshot_passes(self):
        validate_strict_snapshot(**valid())

    def assertRejected(self, **overrides):
        with self.assertRaises(Reject):
            validate_strict_snapshot(**valid(**overrides))

    def test_stale_base_rejected(self):
        self.assertRejected(final_main="e" * 40)

    def test_stale_head_rejected(self):
        self.assertRejected(final_head="e" * 40)

    def test_changed_merge_sha_rejected(self):
        self.assertRejected(final_merge="e" * 40)

    def test_extra_path_rejected(self):
        self.assertRejected(changed_paths=PATHS + ["README.md"])

    def test_wrong_pr_rejected(self):
        self.assertRejected(final_pr_number=17)

    def test_wrong_candidate_parent_rejected(self):
        self.assertRejected(head_parents=["e" * 40])

    def test_wrong_merge_parents_rejected(self):
        self.assertRejected(merge_parents=[BASE, "e" * 40])

    def test_wrong_merge_tree_rejected(self):
        self.assertRejected(merge_tree="e" * 40)


if __name__ == "__main__":
    unittest.main()
