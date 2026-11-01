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

## Novos controles v0.2.0

| Risco | Mitigação | Limite |
|---|---|---|
| Árvore com muitos arquivos pequenos | Orçamento de bytes agregado `--max-total-bytes` | Não substitui limitação de CPU/tempo fora do processo |
| Diretórios muito profundos | Limite de profundidade `--max-depth` | Arquivos e diretórios excluídos ficam fora da varredura por decisão do operador |
| Substituição do manifesto por symlink durante leitura | `O_NOFOLLOW`, identidade do descritor e comparação de metadados | Não impede toda corrida entre sistemas de arquivos/conteúdo mutável |
| HMAC válido contendo entradas malformadas | Validação de estrutura e caminhos assinados antes do diff | Chave comprometida pode forjar dados dentro do esquema permitido |
| Terminal escape em nomes de arquivos | Escape de nomes na saída texto | JSON ainda contém metadados; proteja o relatório |
| Rollback para um manifesto antigo já assinado | **Não mitigado criptograficamente** | Armazenamento imutável externo ou contador monotônico confiável recomendado |
