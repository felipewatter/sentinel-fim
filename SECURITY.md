# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue describing an exploitable vulnerability.
Use the repository's **Security → Advisories → Report a vulnerability** private reporting feature if enabled. Otherwise contact the maintainer privately using the GitHub profile's available contact method; do not send secret keys or actual sensitive file contents.

## Supported releases

The `main` branch and latest published release are the intended maintenance targets. No backward-security-update promise is made for older versions.

## Defensive limitations

SentinelFIM is a **periodic detection tool**, not an EDR, sandbox, antivirus, or real-time filesystem event monitor. A process with access to both the HMAC key and baseline can forge a new signed baseline. Use a separate user, restrictive filesystem permissions, and off-host backups of state. SHA-256 is collision-resistant for this purpose but cannot detect a change reverted between scans.

A local adversary able to write to the monitored directory concurrently can cause filesystem races; the scanner tries to detect file replacement and concurrent modifications, but it cannot offer a kernel-enforced, fully atomic filesystem snapshot. Consider filesystem snapshots for critical environments.

Do not put actual private keys, credentials, reports with private paths, or signed manifests into a public repository. Avoid using the tool as proof of a system being uncompromised.