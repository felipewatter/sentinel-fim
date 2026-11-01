"""Deterministic, authenticated, fail-closed file integrity monitoring."""
from __future__ import annotations
import fnmatch
import hashlib
import hmac
import json
import os
import secrets
import stat
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

VERSION = 1
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_FILES = 250_000
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024
DEFAULT_MAX_DEPTH = 32
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
CHUNK_SIZE = 1024 * 1024

class FIMError(Exception):
    """Any scan or integrity error that must not be confused with 'clean'."""

@dataclass(frozen=True)
class Settings:
    root: Path
    key: Path
    manifest: Path
    excludes: tuple[str, ...] = ()
    max_bytes: int = DEFAULT_MAX_BYTES
    max_files: int = DEFAULT_MAX_FILES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_depth: int = DEFAULT_MAX_DEPTH

def normalized_path(path: Path) -> Path:
    return path.expanduser().resolve(strict=False)

def ensure_settings(s: Settings) -> Settings:
    if s.root.expanduser().absolute().is_symlink():
        raise FIMError("Root must not be a symbolic link")
    root = normalized_path(s.root)
    raw_key = s.key.expanduser().absolute()
    raw_manifest = s.manifest.expanduser().absolute()
    key = raw_key.parent.resolve() / raw_key.name
    manifest = raw_manifest.parent.resolve() / raw_manifest.name
    if not root.is_dir():
        raise FIMError(f"Root is not a directory: {root}")
    if root.is_symlink():
        raise FIMError("Root must not be a symbolic link")
    if (not all(type(v) is int for v in (s.max_bytes, s.max_files, s.max_total_bytes, s.max_depth))
            or s.max_bytes < 1 or s.max_files < 1
            or s.max_total_bytes < 1 or s.max_total_bytes > MAX_TOTAL_BYTES
            or s.max_depth < 0 or s.max_depth > 128):
        raise FIMError("Invalid scan resource limits")
    if key == manifest:
        raise FIMError("Key and manifest must use different paths")
    for external in (key, manifest):
        if external == root or root in external.parents:
            raise FIMError("Keep key and manifest OUTSIDE the monitored directory")
    for pattern in s.excludes:
        if not pattern or pattern.startswith(("/", "\\")) or ".." in pattern.split("/") or "\\" in pattern:
            raise FIMError(f"Invalid exclude pattern: {pattern!r}")
    return Settings(root, key, manifest, s.excludes, s.max_bytes, s.max_files, s.max_total_bytes, s.max_depth)

def generate_key(filename: Path) -> None:
    path = filename.expanduser().absolute()
    if not path.parent.is_dir():
        raise FIMError("Key parent directory does not exist")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
    except OSError as exc:
        raise FIMError(f"Cannot create key (will not overwrite): {exc}") from exc
    try:
        os.fchmod(fd, 0o600) if hasattr(os, "fchmod") else None
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32).hex().encode("ascii") + b"\n")
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise

def load_key(filename: Path) -> bytes:
    p = filename.expanduser().absolute()
    try:
        info = p.lstat()
        if not stat.S_ISREG(info.st_mode):
            raise FIMError("Key must be a regular file (not a symlink)")
        if os.name == "posix" and info.st_mode & 0o077:
            raise FIMError("Key permissions too broad: chmod 600 <key-file>")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(p, flags)
        with os.fdopen(fd, "rb") as f:
            opened = os.fstat(f.fileno())
            if not stat.S_ISREG(opened.st_mode) or (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
                raise FIMError("Key changed while opening")
            raw = f.read(66)
        if len(raw.strip()) != 64:
            raise ValueError("wrong length")
        return bytes.fromhex(raw.strip().decode("ascii"))
    except (OSError, ValueError, UnicodeError) as exc:
        raise FIMError(f"Cannot load secure key: {type(exc).__name__}") from exc

def canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")

def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON key")
        out[key] = value
    return out

def _check_no_symlink(p: Path) -> None:
    if p.is_symlink():
        raise FIMError(f"Refusing symbolic link as state file: {p}")

def _validate_payload(payload: dict[str, Any]) -> None:
    """An authenticated envelope must also have a well-formed, bounded structure."""
    required = {"schema", "root", "created_at", "excludes", "max_bytes", "max_files", "files"}
    permitted = required | {"max_total_bytes", "max_depth"}
    if set(payload) - permitted or not required.issubset(payload):
        raise FIMError("Unexpected authenticated manifest fields")
    if payload["schema"] != VERSION or not isinstance(payload["root"], str) or not payload["root"]:
        raise FIMError("Malformed manifest identity")
    if not isinstance(payload["created_at"], str) or len(payload["created_at"]) > 80:
        raise FIMError("Malformed manifest timestamp")
    if (not isinstance(payload["excludes"], list)
            or any(not isinstance(p, str) for p in payload["excludes"])):
        raise FIMError("Malformed exclusions")
    for name in ("max_bytes", "max_files", "max_total_bytes", "max_depth"):
        val = payload.get(name, DEFAULT_MAX_TOTAL_BYTES if name == "max_total_bytes" else DEFAULT_MAX_DEPTH)
        if name in ("max_bytes", "max_files"):
            val = payload[name]
        if type(val) is not int or (val < 0 if name == "max_depth" else val < 1):
            raise FIMError("Malformed signed resource limit")
    files = payload["files"]
    if not isinstance(files, dict) or len(files) > payload["max_files"]:
        raise FIMError("Malformed signed file inventory")
    for relative, item in files.items():
        if (not isinstance(relative, str) or not relative or len(relative) > 4096
                or relative.startswith("/") or "\\" in relative
                or any(piece in ("", ".", "..") for piece in relative.split("/"))
                or any(ord(ch) < 32 or ord(ch) == 127 for ch in relative)):
            raise FIMError("Unsafe signed relative filename")
        if not isinstance(item, dict):
            raise FIMError("Malformed signed file entry")
        kind = item.get("type")
        if kind == "file":
            if (set(item) != {"type", "sha256", "size", "mode"}
                    or not isinstance(item["sha256"], str)
                    or len(item["sha256"]) != 64
                    or any(ch not in "0123456789abcdef" for ch in item["sha256"])
                    or type(item["size"]) is not int or item["size"] < 0
                    or type(item["mode"]) is not int or item["mode"] < 0):
                raise FIMError("Malformed signed file digest")
        elif kind == "symlink":
            target = item.get("target_sha256")
            if (set(item) != {"type", "target_sha256"}
                    or not isinstance(target, str) or len(target) != 64
                    or any(ch not in "0123456789abcdef" for ch in target)):
                raise FIMError("Malformed signed symlink fingerprint")
        else:
            raise FIMError("Unsupported manifest file type")


def load_manifest(filename: Path, key: bytes) -> dict[str, Any]:
    p = filename.expanduser().absolute()
    _check_no_symlink(p)
    try:
        info = p.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_MANIFEST_BYTES:
            raise FIMError("Manifest is not a regular file or is too large")
        flags = os.O_RDONLY | (getattr(os, "O_NOFOLLOW", 0))
        fd = os.open(p, flags)
        with os.fdopen(fd, "rb") as source:
            opened = os.fstat(source.fileno())
            if (not stat.S_ISREG(opened.st_mode)
                    or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
                raise FIMError("Manifest changed while opening")
            data = source.read(MAX_MANIFEST_BYTES + 1)
            finished = os.fstat(source.fileno())
        if (len(data) > MAX_MANIFEST_BYTES
                or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                != (finished.st_dev, finished.st_ino, finished.st_size, finished.st_mtime_ns)):
            raise FIMError("Manifest changed or exceeds size limit")
        wrapper = json.loads(data, object_pairs_hook=_unique_pairs)
        if not isinstance(wrapper, dict) or set(wrapper) != {"payload", "mac"}:
            raise FIMError("Malformed manifest envelope")
        payload, mac = wrapper["payload"], wrapper["mac"]
        if not isinstance(mac, str) or len(mac) != 64 or not isinstance(payload, dict):
            raise FIMError("Malformed manifest signature")
        expected = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(mac, expected):
            raise FIMError("MANIFEST AUTHENTICATION FAILED: baseline may be tampered")
        _validate_payload(payload)
        return payload
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise FIMError(f"Cannot read manifest: {type(exc).__name__}") from exc

def atomic_manifest_write(filename: Path, payload: dict[str, Any], key: bytes, *, replace: bool) -> None:
    p = filename.expanduser().absolute()
    if not p.parent.is_dir():
        raise FIMError("Manifest parent directory does not exist")
    _check_no_symlink(p)
    if p.exists() and not replace:
        raise FIMError("Manifest already exists; use approve to accept intentional changes")
    mac = hmac.new(key, canonical(payload), hashlib.sha256).hexdigest()
    blob = canonical({"payload": payload, "mac": mac}) + b"\n"
    if len(blob) > MAX_MANIFEST_BYTES:
        raise FIMError("Manifest exceeds size limit")
    fd, tmpname = tempfile.mkstemp(prefix=".sentinelfim-", dir=p.parent)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        _check_no_symlink(p)
        if replace:
            os.replace(tmpname, p)
        else:
            try:
                os.link(tmpname, p)
            except (OSError, NotImplementedError) as exc:
                raise FIMError(f"Cannot atomically create manifest without overwrite: {type(exc).__name__}") from exc
            os.unlink(tmpname)
        if os.name == "posix":
            directory_fd = os.open(p.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if os.path.exists(tmpname):
            os.unlink(tmpname)

def ignored(relative: str, patterns: tuple[str, ...]) -> bool:
    segments = relative.split("/")
    ancestors = ["/".join(segments[:i]) for i in range(1, len(segments) + 1)]
    return any(fnmatch.fnmatchcase(prefix, pattern) for prefix in ancestors for pattern in patterns)

def _read_file(path: Path, max_bytes: int) -> dict[str, Any]:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode):
        raise FIMError(f"Not a regular file during scan: {path}")
    if before.st_size > max_bytes:
        raise FIMError(f"File over configured size limit: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as f:
        initial = os.fstat(f.fileno())
        if not stat.S_ISREG(initial.st_mode) or (before.st_dev, before.st_ino) != (initial.st_dev, initial.st_ino):
            raise FIMError(f"File changed type/identity: {path}")
        digest = hashlib.sha256()
        bytes_read = 0
        while True:
            buf = f.read(CHUNK_SIZE)
            if not buf:
                break
            bytes_read += len(buf)
            if bytes_read > max_bytes:
                raise FIMError(f"File grew beyond configured size limit: {path}")
            digest.update(buf)
        after = os.fstat(f.fileno())
    # On Windows, st_ctime_ns is not a stable modification timestamp across
    # Python versions and can change when the handle is closed. On POSIX it
    # tracks metadata changes and remains part of our race detection.
    stable_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns")
    if os.name == "posix":
        stable_fields += ("st_ctime_ns",)
    for attr in stable_fields:
        if getattr(initial, attr) != getattr(after, attr):
            raise FIMError(f"File changed while being scanned: {path}")
    if bytes_read != after.st_size:
        raise FIMError(f"Unexpected file size during scan: {path}")
    final = path.lstat()
    if any(getattr(final, attr) != getattr(after, attr) for attr in stable_fields):
        raise FIMError(f"File changed immediately after scanning: {path}")
    return {"type": "file", "sha256": digest.hexdigest(), "size": bytes_read, "mode": stat.S_IMODE(after.st_mode)}

def scan_tree(root: Path, excludes: tuple[str, ...], max_bytes: int, max_files: int,
              max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
              max_depth: int = DEFAULT_MAX_DEPTH) -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    def add(relative: str, path: Path) -> None:
        nonlocal total_bytes
        if ignored(relative, excludes):
            return
        if len(entries) >= max_files:
            raise FIMError("Exceeded max-file-count limit; narrow scan scope")
        if relative.count("/") > max_depth:
            raise FIMError("Directory depth limit exceeded; scan incomplete")
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode):
            entries[relative] = {"type": "symlink", "target_sha256": hashlib.sha256(os.readlink(path).encode("utf-8", "surrogateescape")).hexdigest()}
        elif stat.S_ISREG(info.st_mode):
            remaining = max_total_bytes - total_bytes
            if info.st_size > remaining:
                raise FIMError("Aggregate byte budget exceeded; scan incomplete")
            detail = _read_file(path, min(max_bytes, remaining))
            total_bytes += detail["size"]
            entries[relative] = detail
        else:
            raise FIMError(f"Special file must be excluded explicitly: {relative}")

    def handle_error(exc: OSError) -> None:
        raise FIMError(f"Directory traversal failed: {type(exc).__name__}") from exc

    try:
        for current, directories, files in os.walk(root, topdown=True, followlinks=False, onerror=handle_error):
            parent = Path(current)
            for d in sorted(directories[:]):
                candidate = parent / d
                relative = candidate.relative_to(root).as_posix()
                if ignored(relative, excludes):
                    directories.remove(d)
                elif relative.count("/") + 1 > max_depth:
                    raise FIMError("Directory depth limit exceeded; scan incomplete")
                elif candidate.is_symlink():
                    directories.remove(d)
                    add(relative, candidate)
            directories.sort()
            for name in sorted(files):
                candidate = parent / name
                relative = candidate.relative_to(root).as_posix()
                add(relative, candidate)
    except OSError as exc:
        raise FIMError(f"I/O failure during scan: {type(exc).__name__}") from exc
    return entries

def capture(s: Settings) -> dict[str, Any]:
    s = ensure_settings(s)
    return {
        "schema": VERSION,
        "root": str(s.root),
        "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "excludes": list(s.excludes),
        "max_bytes": s.max_bytes,
        "max_files": s.max_files,
        "max_total_bytes": s.max_total_bytes,
        "max_depth": s.max_depth,
        "files": scan_tree(s.root, s.excludes, s.max_bytes, s.max_files, s.max_total_bytes, s.max_depth),
    }

def verify_settings(payload: dict[str, Any], s: Settings) -> None:
    if payload.get("root") != str(s.root):
        raise FIMError("Root differs from signed baseline")
    if (payload.get("excludes") != list(s.excludes)
            or payload.get("max_bytes") != s.max_bytes
            or payload.get("max_files") != s.max_files
            or payload.get("max_total_bytes", DEFAULT_MAX_TOTAL_BYTES) != s.max_total_bytes
            or payload.get("max_depth", DEFAULT_MAX_DEPTH) != s.max_depth):
        raise FIMError("Scanner settings differ from signed baseline")

def diff(old: dict[str, Any], new: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for relative in sorted(set(old) | set(new)):
        if relative not in old:
            results.append({"change": "added", "path": relative})
        elif relative not in new:
            results.append({"change": "removed", "path": relative})
        elif old[relative] != new[relative]:
            changed_fields = sorted(k for k in set(old[relative]) | set(new[relative]) if old[relative].get(k) != new[relative].get(k))
            results.append({"change": "modified", "path": relative, "fields": changed_fields})
    return results

def check(s: Settings) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    s = ensure_settings(s)
    key = load_key(s.key)
    old = load_manifest(s.manifest, key)
    verify_settings(old, s)
    now = capture(s)
    return now, diff(old["files"], now["files"])
