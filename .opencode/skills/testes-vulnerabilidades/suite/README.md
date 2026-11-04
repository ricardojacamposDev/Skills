# Suíte de testes de vulnerabilidades

Bateria executável da skill `testes-vulnerabilidades`. Tudo aqui é defensivo: leitura de arquivos, requisições GET/OPTIONS não destrutivas em ambiente autorizado e especificações de casos para a suíte do próprio projeto. Nenhum componente executa código do alvo.

## Componentes

| Componente | Uso | Risco |
|---|---|---|
| `verificacao_estatica.py` | Padrões inseguros em código/config (segredos, injeção, XSS, SSRF, crypto, TLS, sessão…) | Somente leitura |
| `verificacao_http.py` | Headers, cookies, CORS, TLS e vazamento em erros | GET/OPTIONS; exige `--autorizado` |
| `casos/*.md` | Especificações de testes dinâmicos para implementar no projeto | Ambiente controlado + dados sintéticos |

## Uso rápido

```bash
# 1) Estático (pode rodar em qualquer repositório)
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py . --json relatorio.json

# 2) Filtrar categorias
python3 suite/verificacao_estatica.py src --categorias SEGREDO,INJECAO_SQL

# 3) Falsos positivos revisados
python3 suite/verificacao_estatica.py . --permitir excecoes.txt
```

Formato do arquivo de exceções (`--permitir`), uma regra por linha:

```
# caminho:linha    — ignora o achado na linha
# caminho:id       — ignora o padrão no arquivo
# caminho          — ignora o arquivo inteiro
src/loja/seed.py:segredo-generico
src/legado/x.py:42
```

```bash
# 4) HTTP — apenas ambiente local/staging autorizado
python3 suite/verificacao_http.py --url http://localhost:3000 --autorizado --json http.json
```

O verificador HTTP recusa alvos sem `--autorizado`, recusa hosts não locais sem `--forcar-externo`, faz apenas GET/OPTIONS com espaçamento entre requisições e interrompe diante de respostas 5xx.

## Códigos de saída (integração em CI)

- `verificacao_estatica.py`: `0` sem achados no nível; `1` quando há achado a partir de `--falhar-em` (padrão `alta`; opções: `media`, `baixa`, `qualquer`, `nunca`); `2` erro de uso.
- `verificacao_http.py`: `0` sem achados altos; `1` com achado alto; `2` falha de conexão.

Exemplo em CI (quebra com achados altos):

```bash
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py . \
  --json relatorio-seguranca.json --falhar-em alta
```

## Regras de uso herdadas das skills

- Achado de bateria é **candidato**, não vulnerabilidade confirmada — classifique com `seguranca-aplicacoes`.
- Segredos aparecem mascarados nos relatórios; nunca os reproduza em issues, commits ou respostas. Encontrou segredo real: rotacione pelo fluxo autorizado.
- Registre falsos positivos com justificativa; nunca suprima em massa.
- Casos dinâmicos exigem contas e dados sintéticos, estado isolado por teste e payloads marcadores inofensivos.
- Ausência de achados não é prova de segurança: informe as classes não cobertas.

## Casos dinâmicos disponíveis

| Arquivo | Classe |
|---|---|
| `casos/autorizacao-idor.md` | IDOR/BOLA, escalada, isolamento de tenants, exports |
| `casos/autenticacao-sessao.md` | Sessão, cookies, fixação, revogação, recuperação de senha |
| `casos/entrada-injecao.md` | SQL, comando, path traversal, limites e tipos |
| `casos/saida-xss.md` | Codificação por contexto, sanitização, CSP |
| `casos/ssrf-redirecionamento.md` | Permitlist de destinos, bypasses, redirect aberto |
| `casos/upload-desserializacao.md` | Upload, extração de ZIP, desserialização nativa |
| `casos/concorrencia-idempotencia.md` | Race conditions, TOCTOU, unicidade, idempotência |
| `casos/erros-exposicao-dados.md` | Stack traces, segredos em logs, exports, dados em URL |
| `casos/redos-limites.md` | ReDoS, aninhamento, limites de corpo e parse |
