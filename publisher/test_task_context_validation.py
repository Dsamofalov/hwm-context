import unittest

from publisher.task_context_contract import Reject
from publisher.task_context_validation import validate_index_entry


class TaskContextIndexValidationTests(unittest.TestCase):
    def test_canonical_regular_blob_accepts(self):
        self.assertEqual(validate_index_entry("tasks/I09-0047/context.json", "100644", "blob"), "I09-0047")
        self.assertIsNone(validate_index_entry("tasks/.gitkeep", "100644", "blob"))

    def test_context_markdown_extra_broad_and_wrong_task_paths_reject(self):
        for path in (
            "tasks/I09-0047/context.md",
            "tasks/I09-0047/extra.json",
            "tasks/anything/context.json",
            "tasks/I9-47/context.json",
        ):
            with self.subTest(path=path), self.assertRaises(Reject):
                validate_index_entry(path, "100644", "blob")

    def test_symlink_executable_tree_and_submodule_reject(self):
        for mode, object_type in (
            ("120000", "blob"),
            ("100755", "blob"),
            ("040000", "tree"),
            ("160000", "commit"),
        ):
            with self.subTest(mode=mode, object_type=object_type), self.assertRaises(Reject):
                validate_index_entry("tasks/I09-0047/context.json", mode, object_type)


if __name__ == "__main__":
    unittest.main()
