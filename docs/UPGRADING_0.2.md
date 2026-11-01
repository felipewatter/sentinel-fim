# Migração segura para SentinelFIM 0.2.0

A versão 0.2.0 adiciona limites de recursos que passam a fazer parte dos parâmetros autenticados do manifesto.

## Compatibilidade

Um manifesto da linha v0.1.x com assinatura HMAC correta permanece aceito pelo `check` **quando os novos limites usam os valores padrão**:

- `--max-total-bytes 1073741824` (1 GiB de conteúdo de arquivos)
- `--max-depth 32`

Se a árvore real exceder o novo orçamento, a verificação falhará com código **2** (cobertura incompleta). Esse resultado é intencional.

## Fluxo recomendado

1. Faça backup **protegido e externo** do manifesto, da chave e de quaisquer relatórios.
2. Atualize o pacote e execute uma verificação com os parâmetros anteriores, mantendo os novos nos padrões.
3. Se a política exigir alteração dos novos limites, revise o conteúdo e os valores escolhidos; a ferramenta recusará comparações com parâmetros divergentes.
4. Para estabelecer nova referência com diferentes limites sem sobrescrever o arquivo antigo: armazene o manifesto antigo em local protegido, gere um **novo manifesto** por `baseline` após aprovação humana e mantenha trilha externa da decisão. O comando `approve` normal só aceita parâmetros iguais aos do manifesto existente.
5. Revogue e substitua a chave se houver suspeita de comprometimento. Isso é uma operação administrativa distinta da migração.

## Exemplo de nova referência

```bash
sentinelfim baseline --root /srv/app --key /seguro/secret.key \
  --manifest /seguro/base-v0.2.json --max-total-bytes 2147483648 --max-depth 40
sentinelfim check --root /srv/app --key /seguro/secret.key \
  --manifest /seguro/base-v0.2.json --max-total-bytes 2147483648 --max-depth 40
```

**Nunca aprove mudanças de integridade sem investigação.** A atualização não substitui uma revisão de incidentes ou snapshots imutáveis.
