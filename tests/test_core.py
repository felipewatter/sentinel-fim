"""Unit and integration regression tests; no external services required."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from sentinelfim.cli import main
from sentinelfim.core import (FIMError, Settings, atomic_manifest_write, check,
                              ensure_settings, generate_key, load_key, load_manifest)

class SentinelTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "project"
        self.root.mkdir()
        self.key = base / "key.key"
        self.manifest = base / "manifest.manifest.json"
        generate_key(self.key)
        self.file = self.root / "app.txt"
        self.file.write_text("hello", encoding="utf-8")
        self.settings = Settings(self.root, self.key, self.manifest)
        self.args = ["--root", str(self.root), "--key", str(self.key), "--manifest", str(self.manifest)]

    def execute(self, command, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = main([command, *self.args, *extra])
        if rc == 2:
            import sys
            sys.__stderr__.write(f"[CI-DIAGNOSTIC] {command}: stdout={out.getvalue()!r} stderr={err.getvalue()!r}\\n")
        return rc, out.getvalue(), err.getvalue()

    def test_initial_baseline_and_clean(self):
        self.assertEqual(self.execute("baseline")[0], 0)
        self.assertEqual(self.execute("check")[0], 0)

    def test_modified_content_detected(self):
        self.execute("baseline")
        self.file.write_text("different", encoding="utf-8")
        rc, out, _ = self.execute("check", "--json")
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["findings"][0]["change"], "modified")

    def test_add_remove_detected(self):
        self.execute("baseline")
        self.file.unlink()
        (self.root / "new.txt").write_text("new")
        _, out, _ = self.execute("check", "--json")
        self.assertEqual({x["change"] for x in json.loads(out)["findings"]}, {"added", "removed"})

    def test_manifest_tampering_fails_closed(self):
        self.execute("baseline")
        wrapper = json.loads(self.manifest.read_text())
        wrapper["payload"]["files"]["app.txt"]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(wrapper))
        self.assertEqual(self.execute("check")[0], 2)
        self.assertEqual(self.execute("approve", "--accept-changes")[0], 2)

    def test_wrong_key_fails(self):
        self.execute("baseline")
        other = self.key.parent / "other.key"
        generate_key(other)
        with self.assertRaises(FIMError):
            check(Settings(self.root, other, self.manifest))

    def test_cannot_overwrite_baseline(self):
        self.execute("baseline")
        self.assertEqual(self.execute("baseline")[0], 2)

    def test_explicit_approval_only(self):
        self.execute("baseline")
        self.file.write_text("approved")
        self.assertEqual(self.execute("approve")[0], 2)
        self.assertEqual(self.execute("approve", "--accept-changes")[0], 0)
        self.assertEqual(self.execute("check")[0], 0)

    def test_excluded_paths(self):
        (self.root / "cache").mkdir()
        (self.root / "cache" / "tmp.txt").write_text("cache")
        self.assertEqual(self.execute("baseline", "--exclude", "cache", "--exclude", "cache/**")[0], 0)
        (self.root / "cache" / "tmp.txt").write_text("changed")
        self.assertEqual(self.execute("check", "--exclude", "cache", "--exclude", "cache/**")[0], 0)
        self.assertEqual(self.execute("check")[0], 2)

    def test_resource_limit_not_silent(self):
        self.file.write_text("01234567890123456789")
        self.assertEqual(self.execute("baseline", "--max-file-bytes", "10")[0], 2)

    def test_no_secret_material_in_manifest(self):
        self.execute("baseline")
        self.assertNotIn(load_key(self.key).hex(), self.manifest.read_text())
        self.assertNotIn("hello", self.manifest.read_text())

    def test_duplicate_json_keys_rejected(self):
        self.execute("baseline")
        self.manifest.write_text('{"mac":"aa","mac":"bb","payload":{}}')
        self.assertEqual(self.execute("check")[0], 2)

    def test_key_is_non_overwriting(self):
        with self.assertRaises(FIMError):
            generate_key(self.key)

    def test_symlink_in_directory_is_hashed_not_followed(self):
        target = self.key.parent / "external.txt"
        target.write_text("TOP SECRET")
        sym = self.root / "pointer"
        try:
            sym.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks not available on host")
        self.execute("baseline")
        wrapper = load_manifest(self.manifest, load_key(self.key))
        self.assertEqual(wrapper["files"]["pointer"]["type"], "symlink")
        self.assertNotIn("TOP SECRET", self.manifest.read_text())
        target.write_text("changed target")
        self.assertEqual(self.execute("check")[0], 0)
        sym.unlink()
        sym.symlink_to(self.root / "app.txt")
        self.assertEqual(self.execute("check")[0], 1)

    def test_key_symlink_rejected(self):
        other = self.key.parent / "link.key"
        try:
            other.symlink_to(self.key)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks not available on host")
        with self.assertRaises(FIMError):
            load_key(other)
        self.execute("baseline")
        self.assertEqual(main(["check", "--root", str(self.root), "--key", str(other), "--manifest", str(self.manifest)]), 2)

    def test_manifest_symlink_rejected(self):
        self.execute("baseline")
        other = self.key.parent / "link.json"
        try:
            other.symlink_to(self.manifest)
        except (NotImplementedError, OSError):
            self.skipTest("Symlinks not available on host")
        self.assertEqual(main(["check", "--root", str(self.root), "--key", str(self.key), "--manifest", str(other)]), 2)

    def test_metadata_change_detected_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX mode bits")
        self.execute("baseline")
        self.file.chmod(0o600)
        self.assertEqual(self.execute("check")[0], 1)

    def test_root_outside_state(self):
        with self.assertRaises(FIMError):
            ensure_settings(Settings(self.root, self.root / "key", self.manifest))

    def test_path_names_unicode_and_spaces(self):
        (self.root / "segurança 1.txt").write_text("OK")
        self.execute("baseline")
        self.assertEqual(self.execute("check")[0], 0)

    def test_json_output_machine_readable_error(self):
        rc, out, _ = self.execute("check", "--json")
        self.assertEqual(rc, 2)
        self.assertEqual(json.loads(out)["status"], "error")

    def test_aggregate_bytes_limit_is_fail_closed(self):
        (self.root / "second.txt").write_text("sixsix", encoding="utf-8")
        rc, out, err = self.execute("baseline", "--max-total-bytes", "10")
        self.assertEqual(rc, 2)
        self.assertFalse(self.manifest.exists(), "Incomplete scan must not create baseline")
        self.assertEqual(self.execute("baseline", "--max-total-bytes", "12")[0], 0)
        self.assertEqual(self.execute("check", "--max-total-bytes", "12")[0], 0)
        self.assertEqual(self.execute("check")[0], 2, "Signed limits must match command")

    def test_directory_depth_limit_fails_not_silently_omitting_files(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "note.txt").write_text("nested content", encoding="utf-8")
        self.assertEqual(self.execute("baseline", "--max-depth", "0")[0], 2)
        self.assertFalse(self.manifest.exists())
        self.assertEqual(self.execute("baseline", "--max-depth", "1")[0], 0)
        self.assertEqual(self.execute("check", "--max-depth", "1")[0], 0)
        self.assertEqual(self.execute("check", "--max-depth", "2")[0], 2)

    def test_excluded_directory_does_not_consume_depth(self):
        nested = self.root / "ignored"
        nested.mkdir()
        (nested / "temp.txt").write_text("excluded", encoding="utf-8")
        self.assertEqual(
            self.execute("baseline", "--max-depth", "0", "--exclude", "ignored")[0], 0)
        self.assertEqual(
            self.execute("check", "--max-depth", "0", "--exclude", "ignored")[0], 0)

    def test_legacy_signed_baseline_compatible_with_default_budgets(self):
        self.assertEqual(self.execute("baseline")[0], 0)
        key = load_key(self.key)
        payload = load_manifest(self.manifest, key)
        payload.pop("max_total_bytes")
        payload.pop("max_depth")
        atomic_manifest_write(self.manifest, payload, key, replace=True)
        self.assertEqual(self.execute("check")[0], 0)

    def test_signed_manifest_with_unsafe_path_is_rejected(self):
        self.assertEqual(self.execute("baseline")[0], 0)
        key = load_key(self.key)
        payload = load_manifest(self.manifest, key)
        payload["files"]["../outside.txt"] = payload["files"].pop("app.txt")
        atomic_manifest_write(self.manifest, payload, key, replace=True)
        self.assertEqual(self.execute("check")[0], 2)
        with self.assertRaises(FIMError):
            load_manifest(self.manifest, key)

    def test_signed_manifest_rejects_malformed_file_digests(self):
        self.assertEqual(self.execute("baseline")[0], 0)
        key = load_key(self.key)
        payload = load_manifest(self.manifest, key)
        payload["files"]["app.txt"]["sha256"] = "not-a-sha256"
        atomic_manifest_write(self.manifest, payload, key, replace=True)
        self.assertEqual(self.execute("check")[0], 2)

    def test_report_path_control_characters_are_escaped(self):
        if os.name != "posix":
            self.skipTest("POSIX filenames")
        self.assertEqual(self.execute("baseline")[0], 0)
        (self.root / "line\nbreak.txt").write_text("safe", encoding="utf-8")
        rc, out, _ = self.execute("check")
        self.assertEqual(rc, 1)
        self.assertNotIn("line\nbreak.txt", out)
        self.assertIn("line\\nbreak.txt", out)

    def test_invalid_resource_limits_fail_before_writing(self):
        for arg, value in [("--max-depth", "-1"), ("--max-depth", "129"),
                           ("--max-total-bytes", "0"), ("--max-total-bytes", "5000000000")]:
            self.assertEqual(self.execute("baseline", arg, value)[0], 2)
        self.assertFalse(self.manifest.exists())

if __name__ == "__main__":
    unittest.main()
