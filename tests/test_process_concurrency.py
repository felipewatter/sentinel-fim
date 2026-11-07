"""Cross-process races: atomic baseline creation, manifest verification and approval."""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory
import subprocess
import sys
import unittest

from sentinelfim.core import Settings, check, generate_key, load_key, load_manifest


class ProcessRaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        folder = Path(self.temp.name)
        self.root = folder / "watched"
        self.root.mkdir()
        self.file = self.root / "entry.txt"
        self.file.write_text("initial data", encoding="utf-8")
        self.key = folder / "key.txt"
        self.manifest = folder / "baseline.json"
        generate_key(self.key)
        self.settings = Settings(self.root, self.key, self.manifest)
        self.base = [sys.executable, "-m", "sentinelfim"]
        self.common = ["--root", str(self.root), "--key", str(self.key),
                       "--manifest", str(self.manifest)]

    def command(self, operation, extra=()):
        return subprocess.run(
            [*self.base, operation, *self.common, *extra],
            capture_output=True, text=True, timeout=30, check=False,
        )

    def test_atomic_baseline_creation_has_only_one_winner(self):
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: self.command("baseline"), range(6)))
        self.assertEqual(sum(p.returncode == 0 for p in results), 1,
                         [p.stderr for p in results])
        self.assertTrue(all(p.returncode in (0, 2) for p in results))
        self.assertEqual(self.command("check").returncode, 0)
        self.assertEqual(check(self.settings)[1], [])

    def test_readers_and_approvers_never_observe_torn_manifest(self):
        self.assertEqual(self.command("baseline").returncode, 0)
        self.file.write_text("updated content", encoding="utf-8")
        tasks = (["approve"] * 3) + (["check"] * 6)

        def execute(operation):
            extra = ["--accept-changes"] if operation == "approve" else []
            return self.command(operation, extra)

        with ThreadPoolExecutor(max_workers=9) as pool:
            results = list(pool.map(execute, tasks))
        self.assertTrue(all(p.returncode in (0, 1) for p in results),
                        [(p.returncode, p.stderr) for p in results])
        self.assertIsInstance(load_manifest(self.manifest, load_key(self.key)), dict)
        self.assertEqual(self.command("check").returncode, 0)


if __name__ == "__main__":
    unittest.main()
