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
## Endurecimento na versão 0.2.0

Os manifestos autenticados são verificados quanto ao esquema, tipos e formatos de cada entrada. O manifesto é lido por descritor com validação da identidade do arquivo e restrição de tamanho, mitigando substituições de links entre verificações.

Limites de **bytes totais** e **profundidade da árvore** agora completam os limites individuais de arquivos. Qualquer orçamento excedido retorna erro e impede relatório limpo ou criação/aprovação incompleta. Eles também ficam registrados no manifesto autenticado; limites diferentes exigem uma aprovação explícita.

Manifestos produzidos pela v0.1.x continuam aceitos com limites padrão. A chave e o manifesto devem permanecer **fora da raiz monitorada** e em armazenamento com acesso restrito. Não existe mecanismo anti-rollback externo: quem consegue repor uma versão antiga assinada do manifesto pode reverter o estado de referência. Para maior segurança, use armazenamento imutável ou controle de versões externo com auditoria de aprovação.

Nomes de arquivos são considerados entrada não confiável; na saída texto, caracteres de controle são escapados. A saída JSON contém nomes relativos e outros metadados potencialmente sensíveis e requer cuidados de acesso.
