# Threat Model and Security Architecture

## Assets

- Monitored files/directories: contents and POSIX permission bits.
- HMAC key: 256-bit secret used to authenticate baselines.
- Baseline manifest: canonical JSON containing relative file paths, SHA-256 digests, file sizes, permission bits, and symlink-target fingerprints.

## Trust boundaries

1. **Key** remains external to the monitored root, with restrictive file permissions.
2. **Manifest** stays external to the monitored root and is authenticated before any comparison or approval.
3. **Filesystem scan** handles untrusted names, symlinks and potentially concurrent writes.
4. **CI** executes tests only; it does not hold security keys.

## Controls

| Scenario | Mitigation | Limit |
|---|---|---|
| Replace or modify file | SHA-256 content digest | Reverted files between scans go unnoticed |
| Modify permissions | Compare mode bits | Not all ACLs are modeled; Windows mode behavior differs |
| Tamper with baseline | HMAC-SHA256 using separate key | Compromised key defeats authenticity |
| Change a link destination | Hash literal link target, never follow it | Does not detect changes to a linked target outside root |
| Concurrent file rewrite | Compare inode, device, mtime, ctime and size around read | No atomic whole-tree snapshot guarantee |
| Accidental baseline overwrite | First baseline only, approve requires explicit flag | Authorized approver can accept malicious changes |
| Excessive traversal | File-count and per-file-size limits | Very large trees still consume time/CPU |
| Key exposure | 0600 POSIX permission check; no key output | Windows ACLs and state directory ACLs must be configured separately |

## Assumptions

- The host, interpreter and cryptographic standard library are trusted.
- Private state is not shared publicly or writable by the same untrusted principals as monitored application files.
- The tool operates with read permission and is not run inside an untrusted working directory with executable hooks.
- The administrator investigates reports and approves updates only after review.

## Non-goals

No real-time event collection, SIEM transport, cloud storage, forensic timeline, YARA scanning, alert webhooks, data encryption, automatic repair, or system-wide malware certification.
