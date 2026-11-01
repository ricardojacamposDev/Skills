---
name: pesquisa-vulnerabilidades
description: Conduz pesquisa defensiva de vulnerabilidades, CVE/CWE, advisories, SBOM, código e reprodução segura em ambiente controlado. Use sempre que o usuário pedir investigação de vulnerabilidade, análise de exploitabilidade, validação de finding, pesquisa de CVE ou avaliação autorizada de segurança; exija escopo e autorização antes de qualquer teste ativo.
---

# Pesquisa de vulnerabilidades

Investigue e comprove riscos de forma defensiva, reproduzível e proporcional. O objetivo é estabelecer fatos para correção, não obter acesso, causar impacto ou produzir capacidade ofensiva reutilizável.

## 1. Confirme autorização e escopo

Antes de testes ativos, registre:

- alvos, versões, contas e ambientes permitidos;
- técnicas permitidas e proibidas, janela, limites de taxa e contatos;
- tratamento de dados, critérios de parada e canal para incidentes.

Autorização genérica não cobre terceiros, serviços gerenciados ou produção fora do escopo. Se isso não estiver claro, restrinja-se a análise estática, documentação pública e ambiente local sintético, e peça confirmação.

Não acesse dados além do necessário, não exfiltre informações e não use credenciais reais em provas. Interrompa ao encontrar instabilidade, dados inesperados ou efeito fora do escopo.

## 2. Defina a hipótese

Descreva componente, versão, pré-condições, fronteira de confiança e impacto plausível. Diferencie:

- vulnerabilidade potencial indicada por scanner ou advisory;
- código vulnerável presente;
- caminho vulnerável alcançável;
- vulnerabilidade confirmada no ambiente autorizado;
- exploração ativa conhecida por fonte confiável.

Essas categorias não são intercambiáveis.

## 3. Pesquise fontes e correlacione evidências

Priorize advisories do fornecedor e fontes primárias. Use CVE/NVD, CISA KEV, OSV, GitHub Advisory Database, CWE e boletins de projetos quando pertinentes. Para pesquisa web:

- consulte mais de uma fonte quando a conclusão depender de informação divergente;
- registre URL, data de consulta, versões afetadas e correções indicadas;
- separe fatos publicados, inferências e relatos não confirmados;
- não presuma que o score CVSS representa o risco do ambiente;
- não trate ausência de CVE como evidência de ausência de vulnerabilidade.

Confira versões e ranges no lockfile, imagem, SBOM ou artefato efetivamente implantado, evitando concluir apenas pelo nome da dependência.

## 4. Analise e reproduza com segurança

Prefira a sequência de menor risco: código e configuração, testes unitários, ambiente isolado e, somente se autorizado, teste ativo mínimo.

Para reprodução:

- use container/VM ou ambiente descartável, rede restrita e dados sintéticos;
- fixe a versão vulnerável e mantenha uma versão corrigida como controle quando possível;
- limite a prova ao mínimo que demonstra o impacto;
- capture logs e resultados sem segredos ou dados pessoais;
- não adicione persistência, evasão, propagação, destruição, exfiltração ou confiabilidade operacional à prova de conceito.

Ausência de reprodução significa “não confirmado nas condições testadas”, não “sistema seguro”.

## 5. Classifique sem exagerar

Avalie impacto, alcançabilidade, exposição, privilégios necessários, interação do usuário, mitigações e evidência de exploração. Informe confiança e incertezas. Não classifique como vulnerabilidade uma simples preferência de hardening sem caminho de abuso concreto.

## Formato de entrega

1. **Resumo** — componente, versão, estado da investigação e risco contextual.
2. **Escopo e autorização** — ou limitação para análise passiva.
3. **Evidências** — arquivos/linhas, advisories, SBOM, logs e fontes com datas.
4. **Análise de alcançabilidade** — pré-condições e caminho de ataque em alto nível.
5. **Reprodução segura** — ambiente, resultado e limitações; sem dados sensíveis.
6. **Conclusão** — confirmada, potencial, falso positivo ou inconclusiva, com confiança.
7. **Recomendações** — correção e mitigação priorizadas.

Para executar correção, contenção e validação, use `resposta-vulnerabilidades`. Para revisar controles estruturais além de um finding, use `seguranca-aplicacoes`.
