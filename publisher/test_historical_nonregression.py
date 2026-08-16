from pathlib import Path
import hashlib
import unittest

ROOT = Path(__file__).resolve().parents[1]
PINS = {
    "publisher/historical_ledger_publisher.py": "2402dedf33e8d8596d8f4075e8ee2546854b63e0",
    "publisher/historical_ledger_publisher_v2.py": "e05f6be2640f72b9868149b0f1c0daaa5a942336",
    "publisher/strict_generated_pr_gate.py": "23b786bef0dbe837509bd781d210e5efe9b93c3a",
    "publisher/strict_check_publisher.py": "0a7313bdca802ddf9b3b74bf7dc7ce07dc66ca03",
    ".github/workflows/historical-ledger-publisher.yml": "aa43e11862b3b6e030ea3f241683aa578f82d2a8",
}


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


class HistoricalPublisherNonRegressionTests(unittest.TestCase):
    def test_historical_publisher_and_gate_are_byte_exact(self):
        for path, expected in PINS.items():
            with self.subTest(path=path):
                self.assertEqual(git_blob_sha((ROOT / path).read_bytes()), expected)


if __name__ == "__main__":
    unittest.main()
