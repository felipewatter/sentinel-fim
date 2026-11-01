# SentinelFIM — Authenticated File Integrity Monitoring

[![CI](https://github.com/felipewatter/sentinel-fim/actions/workflows/ci.yml/badge.svg)](https://github.com/felipewatter/sentinel-fim/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB.svg)](https://www.python.org/)
[![Security Policy](https://img.shields.io/badge/security-policy-informational.svg)](SECURITY.md)

**Monitoramento de integridade de arquivos com SHA-256 e bases de referência autenticadas por HMAC-SHA256.** Uma ferramenta de linha de comando, sem dependências de execução externas, destinada a administradores, desenvolvedores, analistas de segurança e equipes Blue Team.

> **Estado do código:** `0.2.0` (beta pública); a release GitHub oficial é publicada separadamente. A versão `v0.1.1` foi o último lançamento anterior. Segurança é uma propriedade que precisa ser verificada continuamente. O projeto ainda não passou por auditoria independente; não utilize como única proteção de produção.

**Repositório oficial:** https://github.com/felipewatter/sentinel-fim

## Sumário

- [Por que este projeto?](#por-que-este-projeto)
- [Funcionalidades implementadas](#funcionalidades-implementadas)
- [Como funciona](#como-funciona)
- [Instalação](#instalação)
- [Primeiros passos](#primeiros-passos)
- [Comandos e parâmetros](#comandos-e-parâmetros)
- [Exemplos de integração](#exemplos-de-integração)
- [Segurança e limitações](#segurança-e-limitações)
- [Testes e GitHub Actions](#testes-e-github-actions)
- [Estrutura do repositório](#estrutura-do-repositório)
- [Contribuição e licença](#contribuição-e-licença)
- [Referências](#referências)

## Por que este projeto?

Um sistema de produção pode sofrer alterações não autorizadas em código, configurações e arquivos de implantação. Monitorar apenas a data de modificação não é suficiente: um hash do conteúdo pode sinalizar modificações, e a autenticação da **própria base de comparação** dificulta a ocultação de alterações por quem não possui a chave.

O SentinelFIM segue a ideia de ferramentas consolidadas de integridade como [AIDE](https://aide.github.io/) e o módulo de [File Integrity Monitoring do Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/), mas tem escopo distinto: uma CLI pequena, auditável, educacional e independente de agentes ou serviços externos. Não é uma substituição completa para elas.

### Casos de uso

- Validar alterações em diretórios de configuração antes e depois de uma janela de manutenção.
- Detectar arquivos novos, removidos ou alterados em uma pasta de implantação estática.
- Comparar artefatos de builds com uma referência aprovada.
- Complementar controles de change management e auditorias de conformidade.
- Produzir saída JSON consumível por scripts locais, agendadores e pipelines.

## Funcionalidades implementadas

| Capacidade | Implementação | Observação |
|---|---|---|
| Hash de conteúdo | SHA-256 em blocos de 1 MiB | Não armazena conteúdo dos arquivos |
| Autenticidade da base | HMAC-SHA256 com chave aleatória de 256 bits | Chave fica separada da pasta monitorada |
| Detecção de mudanças | `added`, `removed`, `modified` | Determinística, com caminhos relativos |
| Permissões | Comparação de `mode` POSIX | Não inclui ACLs completas |
| Links simbólicos | Hash do destino textual do link | **Nunca segue** os links simbólicos |
| Atualização controlada | `approve --accept-changes` | Recusa sobrescrever a base silenciosamente |
| Proteção contra alterações durante leitura | Verificações de dispositivo, inode, tamanho, mtime e ctime | Não substitui snapshots atômicos do sistema de arquivos |
| Segurança operacional | Limites por arquivo, **bytes agregados**, quantidade de arquivos e profundidade da árvore; escrita atômica e falha explícita | Sem executar scripts de arquivos monitorados |
| Relatórios | Texto e JSON (`--json`) | Não divulga conteúdo dos arquivos |
| CLI multiplataforma | Python >= 3.10, biblioteca padrão | Windows, Linux, macOS |
| Qualidade | `unittest`, CI em matriz de sistemas/Python | Execução local sem serviços |

## Como funciona

```text
              Diretório monitorado
                   │
              Varredura local
                   │
            SHA-256 + metadados
                   │
        JSON determinístico (payload)
                   │
 Chave 256 bits ── HMAC-SHA256 ──> Manifesto autenticado
                   │
         check: autentica primeiro
                   │
       Nova varredura + comparação
                   │
         clean / changed / error
```

O manifesto possui um envelope de campos `payload` e `mac`, com serialização JSON canônica (`sort_keys`, separadores constantes, UTF-8). A assinatura usa **HMAC**, não assinatura digital assimétrica; **quem possuir a chave pode autenticar uma nova base**.

A base vincula caminho absoluto da raiz monitorada, lista de exclusões, limites de recursos, versão de esquema e hashes esperados. Se os parâmetros da verificação mudarem, o comando falha em vez de apresentar resultado enganoso.

## Instalação

### Pré-requisitos

- Python 3.10 ou superior.
- Permissão de leitura para a pasta monitorada.
- Um diretório de estado **fora** da pasta monitorada, restrito ao administrador.
- Não requer Docker, Node.js, banco de dados ou conexão com a internet para executar.

### Windows (PowerShell)

```powershell
git clone https://github.com/felipewatter/sentinel-fim.git
cd sentinel-fim
py -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install .
sentinelfim --help
```

Se a política de execução bloquear a ativação, use diretamente `.venv\Scripts\python.exe -m sentinelfim --help`.

### Linux / macOS

```bash
git clone https://github.com/felipewatter/sentinel-fim.git
cd sentinel-fim
python3 -m venv .venv
. .venv/bin/activate
python -m pip install .
sentinelfim --help
```

Também é possível usar `PYTHONPATH=src python -m sentinelfim --help` sem instalação, desde a raiz do código.

> Não existe promessa de disponibilidade no PyPI. Comandos como `pip install sentinelfim` não devem ser usados como instrução de instalação até que o pacote seja efetivamente publicado e validado no índice.

## Primeiros passos

Para o exemplo, considere uma pasta **já existente** `/srv/minha-app` e um diretório de estado pessoal `~/.local/state/sentinelfim`. Adapte para seu ambiente.

### 1. Criar diretório de estado e chave (Linux/macOS)

```bash
mkdir -p ~/.local/state/sentinelfim
chmod 700 ~/.local/state/sentinelfim
sentinelfim keygen --key ~/.local/state/sentinelfim/app.key
```

A chave é criada com permissões POSIX `0600`. O programa se recusa a sobrescrever uma chave existente. **Faça backup seguro:** perder a chave torna impossível verificar a autenticidade das bases antigas.

### 2. Criar a referência inicial

```bash
sentinelfim baseline \
  --root /srv/minha-app \
  --key ~/.local/state/sentinelfim/app.key \
  --manifest ~/.local/state/sentinelfim/app.manifest.json \
  --exclude '.git' --exclude '.git/**'
```

Exemplo de retorno:

```text
SentinelFIM: baseline_created | tracked=42 | changes=0
```

**Atenção:** a base inicial deve ser criada em um sistema já considerado confiável. O programa não consegue determinar se os arquivos estavam comprometidos *antes* do baseline.

### 3. Verificar alterações

```bash
sentinelfim check \
  --root /srv/minha-app \
  --key ~/.local/state/sentinelfim/app.key \
  --manifest ~/.local/state/sentinelfim/app.manifest.json \
  --exclude '.git' --exclude '.git/**'
```

Exemplo de retorno **ilustrativo** após mudanças:

```text
SentinelFIM: changed | tracked=43 | changes=2
  modified  config/app.yml
  added     public/notes.txt
```

### 4. Obter relatório JSON

```bash
sentinelfim check \
  --root /srv/minha-app \
  --key ~/.local/state/sentinelfim/app.key \
  --manifest ~/.local/state/sentinelfim/app.manifest.json \
  --exclude '.git' --exclude '.git/**' \
  --json
```

Exemplo resumido:

```json
{
  "status": "changed",
  "tracked": 43,
  "findings": [
    {"change": "added", "path": "public/notes.txt"},
    {"change": "modified", "fields": ["sha256", "size"], "path": "config/app.yml"}
  ]
}
```

### 5. Aprovar mudanças intencionais

**Somente depois de investigar** os arquivos sinalizados:

```bash
sentinelfim approve \
  --root /srv/minha-app \
  --key ~/.local/state/sentinelfim/app.key \
  --manifest ~/.local/state/sentinelfim/app.manifest.json \
  --exclude '.git' --exclude '.git/**' \
  --accept-changes
```

Esse comando **substitui a referência anterior** pela situação atual, registrando os achados na saída. Guarde um backup seguro da base antiga para investigação e auditoria; o programa não mantém versões históricas automaticamente.

### Windows: exemplo de comandos

```powershell
New-Item -ItemType Directory -Force "$HOME\sentinelfim-state"
sentinelfim keygen --key "$HOME\sentinelfim-state\app.key"
sentinelfim baseline --root "C:\MeuApp" --key "$HOME\sentinelfim-state\app.key" --manifest "$HOME\sentinelfim-state\app.manifest.json"
sentinelfim check --root "C:\MeuApp" --key "$HOME\sentinelfim-state\app.key" --manifest "$HOME\sentinelfim-state\app.manifest.json" --json
```

**No Windows:** configure ACLs de NTFS para limitar quem pode ler a chave e alterar a referência. O projeto não automatiza a configuração de ACLs Windows.

## Comandos e parâmetros

| Comando | Objetivo |
|---|---|
| `sentinelfim keygen --key PATH` | Criar chave HMAC aleatória, sem substituir outra existente |
| `sentinelfim baseline ...` | Criar manifesto inicial autenticado (apenas se ainda não existir) |
| `sentinelfim check ...` | Comparar o estado atual com o manifesto autenticado |
| `sentinelfim approve ... --accept-changes` | Atualizar explicitamente a referência após revisão |

As opções exigidas em `baseline`, `check` e `approve` são `--root`, `--key`, `--manifest`.

| Opção | Padrão | Comportamento |
|---|---|---|
| `--exclude GLOB` | Nenhuma | Excluir caminhos com padrões relativos; repetível |
| `--max-file-bytes N` | 104857600 (100 MiB) | Falha ao encontrar arquivo maior que o limite |
| `--max-files N` | 250000 | Falha se a contagem ultrapassar o limite |
| `--json` | Desligado | Escreve um objeto JSON em stdout |
| `--accept-changes` | Desligado | Confirmação obrigatória em `approve` |

**Regras de exclusão:** os padrões são relativos à raiz, utilizam `/` como separador e operam por correspondência `fnmatch`. Para ignorar uma árvore, forneça `--exclude 'cache' --exclude 'cache/**'`. A escolha de exclusões fica **assinada** no manifesto, portanto deve ser repetida exatamente na verificação.

**Códigos de saída:**

| Código | Significado | Ação recomendada |
|---|---|---|
| `0` | Limpo, baseline criado ou aprovação concluída | Prosseguir |
| `1` | `check` encontrou mudanças | Investigar e, se necessário, bloquear etapa automatizada |
| `2` | Erro, base inválida, chave incorreta, recurso inacessível ou limite excedido | Falhar em modo seguro; nunca interpretar como limpo |

## Exemplos de integração

### GitHub Actions / CI

O próprio repositório inclui a matriz `.github/workflows/ci.yml` para compilar e testar em sistemas operacionais e versões Python distintas. Ela **não** exige armazenar uma chave secreta real no GitHub, pois os testes criam chaves efêmeras.

Para integrar o SentinelFIM ao seu pipeline de entrega, armazene a base assinada e a chave em um local protegido, de preferência fora do repositório e com controle de acesso separado. Execute `check` e trate exit codes `1` e `2` como falha. Não faça `approve` automaticamente em pipelines não confiáveis.

### Linux cron (exemplo)

Agende uma verificação com todos os argumentos anteriores; redirecione apenas o relatório, não o conteúdo do arquivo de chave. Em automações, trate códigos de saída de modo explícito. Para escopos críticos, prefira agendador com logs persistentes, notificações e supervisão operacional.

### Integração com SIEM

Consuma o JSON produzido por `--json` e mapeie os campos `status`, `tracked`, `findings[].path`, `findings[].change` e `findings[].fields`. Não envie o arquivo da chave ou a base HMAC a canais de logs públicos.

## Segurança e limitações

### Controles importantes

- **Não executa nenhum código** de arquivos monitorados.
- **Não segue symlinks** (incluindo links que apontam para fora da raiz), mas registra seus destinos textuais em forma de hash.
- Recusa chave ou manifesto em links simbólicos e exige, em POSIX, chave legível apenas pelo proprietário (`0600`).
- Impede por configuração que chave e manifesto fiquem dentro da raiz monitorada.
- Autentica o manifesto **antes** de confiar em seus dados.
- Salva bases por arquivo temporário e substituição atômica no mesmo diretório, com `fsync`.
- Registra hashes, tamanhos, modos de permissão e **caminhos relativos**, nunca conteúdo completo dos arquivos.
- Limita tamanho individual de arquivos, quantidade monitorada e tamanho do manifesto.

### Limites explícitos

1. **Não é antivírus nem EDR:** não identifica automaticamente malware, nem substitui Wazuh/AIDE.
2. **Não é monitoramento em tempo real:** uma mudança revertida entre verificações pode passar despercebida.
3. **Não oferece snapshot atômico da árvore:** as verificações reduzem o risco de concorrência por arquivo, mas não eliminam ataques de corrida ou alterações entre arquivos.
4. **HMAC exige confidencialidade da chave:** quem tiver acesso de escrita à base e à chave pode forjar uma nova referência válida.
5. **Não armazena histórico interno nem envia alertas remotos:** use versionamento de referência em storage privado ou integrações do seu ambiente.
6. **Não compara ACLs avançadas:** a verificação de `mode` não cobre ACLs NTFS e ACLs POSIX adicionais.
7. **Não varre conteúdos referenciados por symlink:** o alvo deve ser incluído como caminho real separado, se necessário.
8. **Não verifica pastas vazias nem metadados completos de diretórios.**
9. **Não considere `clean` sinônimo de ambiente seguro:** significa apenas ausência de diferença no escopo e nos atributos definidos.

Veja [Threat Model](docs/THREAT_MODEL.md) e [Security Policy](SECURITY.md).

## Atualização da v0.1.x para v0.2.0

Novos parâmetros de segurança:

```bash
sentinelfim baseline --root ./diretorio --key ../estado/secret.key --manifest ../estado/base.json --max-total-bytes 1073741824 --max-depth 32
sentinelfim check --root ./diretorio --key ../estado/secret.key --manifest ../estado/base.json --max-total-bytes 1073741824 --max-depth 32
```

**Compatibilidade:** manifestos v0.1.x autenticados permanecem válidos com esses limites padrão. O HMAC continua sendo verificado antes de qualquer comparação. Se alterar os limites, o `check` retorna erro de configurações diferentes, em vez de indicar que está limpo. Após uma revisão explícita do conteúdo, reavalie com o procedimento documentado em [docs/UPGRADING_0.2.md](docs/UPGRADING_0.2.md).

A validação é **periódica**, não monitora alterações em tempo real. Valores de caminhos em saídas texto são escapados para impedir caracteres de controle ou quebras de linha dentro de um registro.

## Testes e GitHub Actions

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python -m compileall -q src
python -m sentinelfim --help
```

Os testes cobrem mudanças de conteúdo, arquivos adicionados/removidos, alterações em permissões POSIX, exclusões, base adulterada, chave errada, limites, aprovação, symlinks, JSON e Unicode.

O CI possui token restrito a **`contents: read`**, evita segredos, usa SHA completo para as Actions de checkout e setup-python e executa testes em Windows, Linux e macOS. Consulte a [documentação de segurança do GitHub Actions](https://docs.github.com/en/actions/reference/security/secure-use).

## Estrutura do repositório

```text
sentinel-fim/
├── .github/
│   ├── workflows/ci.yml             # Matriz de CI e segurança do workflow
│   ├── dependabot.yml               # Monitoramento de atualizações
│   └── ISSUE_TEMPLATE/bug_report.md
├── docs/THREAT_MODEL.md             # Modelo de ameaças e limitações
├── src/sentinelfim/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py                       # Comandos, mensagens, exit codes
│   └── core.py                      # Scan, HMAC, leitura/escrita e diff
├── tests/test_core.py               # Testes funcionais e adversariais
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── CODE_OF_CONDUCT.md
├── CONTRIBUTING.md
├── LICENSE                          # Texto MIT integral
├── SECURITY.md
├── pyproject.toml                   # Empacotamento e CLI instalável
└── README.md
```

## Contribuição e licença

Contribuições são bem-vindas. Leia [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) e [SECURITY.md](SECURITY.md). Vulnerabilidades de segurança devem ser comunicadas em privado, e nunca com dados reais em issues públicas.

**Licença:** [MIT](LICENSE), © 2026 Felipe Watter. Código-fonte público **não** significa que todas as instalações estejam certificadas ou livres de falhas.

## Referências

- [AIDE — Advanced Intrusion Detection Environment](https://aide.github.io/)
- [Wazuh — File Integrity Monitoring](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/)
- [OWASP — GitHub Actions Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GitHub_Actions_Security_Cheat_Sheet.html)
- [GitHub — Secure use reference](https://docs.github.com/en/actions/reference/security/secure-use)
- [NIST FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104)

---

**Maintainer:** [@felipewatter](https://github.com/felipewatter) · Projeto educacional e defensivo de segurança.