# Changelog

## [0.2.0] — 2026-11-01

- Limite agregado de bytes `--max-total-bytes` (padrão 1 GiB; máximo 4 GiB), sem silently-skipped arquivos: falha completa com exit 2 caso excedido.
- Limite de profundidade `--max-depth` (padrão 32, máximo 128), protegido por assinatura do manifesto.
- Manifesto assinado tem estrutura validada de forma restrita, incluindo caminhos relativos seguros, digests SHA-256, symlinks e tipos de metadados.
- A leitura do manifesto agora usa `O_NOFOLLOW` quando disponível, descritor aberto, comparação de inode e metadados contra alterações simultâneas e teto de 32 MiB durante a leitura.
- Compatibilidade de leitura com manifestos v0.1.x assinados, quando usados os limites padrão. Limites personalizados novos exigem uma nova aprovação após revisão.
- Caminhos que contêm quebras de linha ou caracteres de controle deixam de ser impressos diretamente em saída texto (escape JSON).
- Cobertura de testes ampliada para limites agregados, profundidade, compatibilidade retroativa, arquivos assinados malformados e proteção contra injeção em terminal.
- CI ampliado para Python 3.10, 3.11, 3.12 e 3.13 em Ubuntu, Windows e macOS; atualizados documentos de ameaças e migração.

## [0.1.1] — 2026-10-31

- Correções de compatibilidade e estabilidade no Windows, sem alterar o escopo de monitoramento de integridade autenticado.

## [0.1.0] — 2026-10-31

- Implementação inicial com SHA-256, HMAC-SHA256, fingerprints de symlinks, aprovação explícita, falha segura e testes de integração.
