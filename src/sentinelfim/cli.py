"""Command-line interface and stable exit codes for SentinelFIM."""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path
from .core import (
    DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, FIMError, Settings, atomic_manifest_write,
    capture, check, ensure_settings, generate_key, load_key,
)

def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="sentinelfim", description="Authenticated file-integrity baselines")
    cmds = root.add_subparsers(dest="command", required=True)
    keygen = cmds.add_parser("keygen", help="Create a private 256-bit HMAC key")
    keygen.add_argument("--key", required=True, type=Path)
    for command in ("baseline", "check", "approve"):
        item = cmds.add_parser(command)
        item.add_argument("--root", required=True, type=Path)
        item.add_argument("--key", required=True, type=Path)
        item.add_argument("--manifest", required=True, type=Path)
        item.add_argument("--exclude", action="append", default=[], metavar="GLOB")
        item.add_argument("--max-file-bytes", type=int, default=DEFAULT_MAX_BYTES)
        item.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
        item.add_argument("--json", action="store_true", help="Machine-readable single JSON object")
        if command == "approve":
            item.add_argument("--accept-changes", action="store_true", help="Required explicit acknowledgement")
    return root

def emit(result: dict, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print(f"SentinelFIM: {result['status']} | tracked={result.get('tracked', 0)} | changes={len(result.get('findings', []))}")
        for finding in result.get("findings", []):
            print(f"  {finding['change']:<9} {finding['path']}")

def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "keygen":
            generate_key(args.key)
            print(f"Key created: {args.key} (keep private; never commit)")
            return 0
        s = ensure_settings(Settings(args.root, args.key, args.manifest, tuple(args.exclude), args.max_file_bytes, args.max_files))
        if args.command == "baseline":
            if s.manifest.exists() or s.manifest.is_symlink():
                raise FIMError("Manifest already exists; refusing to overwrite")
            key = load_key(s.key)
            payload = capture(s)
            atomic_manifest_write(s.manifest, payload, key, replace=False)
            emit({"status": "baseline_created", "tracked": len(payload["files"]), "findings": []}, args.json)
            return 0
        if args.command == "approve" and not args.accept_changes:
            raise FIMError("Approval requires --accept-changes")
        payload, findings = check(s)
        if args.command == "approve":
            atomic_manifest_write(s.manifest, payload, load_key(s.key), replace=True)
            emit({"status": "changes_approved", "tracked": len(payload["files"]), "findings": findings}, args.json)
            return 0
        emit({"status": "changed" if findings else "clean", "tracked": len(payload["files"]), "findings": findings}, args.json)
        return 1 if findings else 0
    except FIMError as exc:
        if getattr(args, "json", False):
            emit({"status": "error", "message": str(exc), "findings": []}, True)
        else:
            print(f"SentinelFIM ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
