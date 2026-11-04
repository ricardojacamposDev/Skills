---
name: testes-vulnerabilidades
description: Executa bateria padronizada de testes de vulnerabilidade em aplicações web — verificação estática de código, checagens HTTP em ambiente controlado e casos dinâmicos para a suíte do projeto, cobrindo segredos, injeção, XSS, autorização entre usuários/tenants, SSRF, desserialização, sessão, upload, concorrência e exposição de dados. Use ao pedir teste de vulnerabilidades, scan de segurança, validação de segurança antes de release, checagem de headers/cookies ou implementação dos casos negativos de segurança; checagens HTTP e casos dinâmicos exigem ambiente autorizado.
---

# Testes de vulnerabilidades

Bateria padronizada para transformar hipóteses de segurança em evidência observável. Um resultado da bateria é um **candidato a achado**, nunca uma vulnerabilidade confirmada: a confirmação exige alcançabilidade e impacto, conforme `seguranca-aplicacoes`. Os testes não executam código do alvo, não enviam payloads destrutivos e não acessam dados reais.

## 1. Defina escopo e autorização por camada

| Camada | O que faz | Requisitos |
|---|---|---|
| Estática (`suite/verificacao_estatica.py`) | Lê arquivos do repositório e procura padrões inseguros conhecidos | Nenhum; serve para qualquer código |
| HTTP (`suite/verificacao_http.py`) | Requisições GET não destrutivas; headers, cookies, CORS, TLS e vazamento em erros | `--url` de ambiente local/staging **e** flag `--autorizado` |
| Casos dinâmicos (`suite/casos/`) | Especificações de teste para implementar na suíte do próprio projeto | Ambiente controlado, contas e dados sintéticos |

Sem autorização explícita, restrinja-se à camada estática. Nunca aponte checagens HTTP para produção, terceiros ou sistemas sem permissão. Interrompa diante de respostas 5xx, instabilidade ou efeito fora do escopo — resultado parcial registrado vale mais que bateria completa em ambiente instável.

## 2. Execute na ordem de menor risco

1. **Estático:**
   `python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py <caminho> --json relatorio.json`
2. **Triagem:** confirme cada achado lendo o código e o caminho de execução; registre falsos positivos em `--permitir` com justificativa técnica — nunca supressão ampla e permanente sem revisão.
3. **HTTP (se autorizado):**
   `python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_http.py --url http://localhost:PORTA --autorizado`
4. **Casos dinâmicos:** implemente os casos aplicáveis no framework de testes do projeto, com dados sintéticos e estado isolado por teste; reutilize fixtures e seletores conforme `testes-qualidade-web`.

## 3. Classifique com evidência

Cada achado sai com severidade (alta/média/baixa) e confiança (alta/média/baixa). Confiança alta em verificação estática significa apenas que o padrão existe no arquivo — não que é alcançável por entrada externa. Classifique o estado final de cada item:

- **confirmado:** caminho de abuso demonstrado em teste;
- **hipótese:** padrão presente, alcance não verificado;
- **fragilidade:** controle ausente ou fraco sem exploração demonstrada;
- **falso positivo:** justificativa registrada.

Segredos detectados: informe apenas localização e tipo, recomende rotação pelo fluxo autorizado e nunca reproduza o valor em relatório, log, commit ou conversa — os relatórios da bateria já mascaram os valores.

## 4. Corrija e reteste

- Aplique o menor patch que remova a causa raiz e procure variantes do mesmo padrão no escopo afetado.
- Adicione regressão que falhe na versão vulnerável e passe na corrigida, quando seguro e viável.
- Rerode a bateria e os testes do projeto; ausência de achados da bateria não equivale a sistema seguro — informe o que ela não cobre.
- Em CI, use `--falhar-em` e `--json` para quebrar o build conforme a política do projeto, sem tratar falso positivo como incidente.

## Formato de entrega

1. **Escopo e autorização** — camadas executadas, ambiente e limites.
2. **Achados priorizados** — categoria, local, severidade, confiança e estado (confirmado/hipótese/fragilidade/falso positivo).
3. **Evidências** — relatórios gerados, sem segredos ou dados pessoais.
4. **Correções e reteste** — mudanças, teste de regressão e resultado antes/depois.
5. **Risco residual** — classes não cobertas pela bateria e áreas não examinadas.

Para investigar uma CVE específica, use `pesquisa-vulnerabilidades`; para priorizar e implantar correções, `resposta-vulnerabilidades`; para modelagem de ameaças e revisão estrutural de controles, `seguranca-aplicacoes`; para integrar os casos dinâmicos à suíte existente, `testes-qualidade-web`.
