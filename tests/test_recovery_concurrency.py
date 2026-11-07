"""Concurrent verification and recovery regression coverage; no external services."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from sentinelfim.cli import main
from sentinelfim.core import FIMError, Settings, check, generate_key


class RecoveryAndConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = base / "watched"
        self.root.mkdir()
        self.key = base / "key"
        self.manifest = base / "baseline.json"
        (self.root / "file.txt").write_text("original", encoding="utf-8")
        generate_key(self.key)
        self.settings = Settings(self.root, self.key, self.manifest)
        self.assertEqual(main([
            "baseline", "--root", str(self.root), "--key", str(self.key),
            "--manifest", str(self.manifest),
        ]), 0)

    def test_concurrent_checks_are_read_only_and_deterministic(self):
        original = self.manifest.read_bytes()
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: check(self.settings)[1], range(32)))
        self.assertTrue(all(findings == [] for findings in results))
        self.assertEqual(self.manifest.read_bytes(), original)

    def test_corrupt_manifest_fails_closed_then_recovers_from_trusted_copy(self):
        saved = self.manifest.read_bytes()
        self.manifest.write_bytes(b'{"payload":{},"mac":"bad"}')
        with self.assertRaises(FIMError):
            check(self.settings)
        self.manifest.write_bytes(saved)
        self.assertEqual(check(self.settings)[1], [])

    def test_missing_then_restored_file_is_reported_then_clean(self):
        file = self.root / "file.txt"
        original = file.read_bytes()
        file.unlink()
        self.assertTrue(check(self.settings)[1])
        file.write_bytes(original)
        self.assertEqual(check(self.settings)[1], [])


if __name__ == "__main__":
    unittest.main()
