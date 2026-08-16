import hashlib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def git_blob_sha(data):
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


class TaskContextStageNonRegressionTests(unittest.TestCase):
    def test_existing_historical_and_task_context_publisher_blobs_are_unchanged(self):
        expected = {
            ".github/workflows/historical-ledger-publisher.yml": "aa43e11862b3b6e030ea3f241683aa578f82d2a8",
            "publisher/historical_ledger_publisher.py": "2402dedf33e8d8596d8f4075e8ee2546854b63e0",
            "publisher/historical_ledger_publisher_v2.py": "e05f6be2640f72b9868149b0f1c0daaa5a942336",
            "publisher/strict_generated_pr_gate.py": "23b786bef0dbe837509bd781d210e5efe9b93c3a",
            ".github/workflows/task-context-publisher.yml": "0977bcc4c22d961e06220e3d01317204552dbc71",
            "publisher/task_context_contract.py": "065707cf0b4183bcbf2d0c947cb28285489de561",
            "publisher/task_context_publisher.py": "cd772b71e6c21c90b6e04211420818eb0a3f4802",
            "publisher/task_context_strict_gate.py": "b70ade85a718fcb3dfdf6aca397e23995597b951",
            "publisher/task_context_validation.py": "7682a6c59dc9e032e1b35e152da63094b35bf9f8",
        }
        for path, blob_sha in expected.items():
            with self.subTest(path=path):
                self.assertEqual(git_blob_sha((ROOT / path).read_bytes()), blob_sha)

    def test_stager_does_not_import_or_invoke_existing_publisher_mutation_runtime(self):
        stager = (ROOT / "publisher" / "task_context_stager.py").read_text(encoding="utf-8")
        uploader = (ROOT / "publisher" / "task_context_stage_uploader.py").read_text(encoding="utf-8")
        for source in (stager, uploader):
            self.assertNotIn("task_context_publisher", source)
            self.assertNotIn("task_context_strict_gate", source)
            self.assertNotIn("historical_ledger_publisher", source)


if __name__ == "__main__":
    unittest.main()
