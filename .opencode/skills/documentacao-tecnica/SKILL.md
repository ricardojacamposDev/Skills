---
name: documentacao-tecnica
description: Cria e mantém documentação técnica útil — ADRs, runbooks, documentação de API, README e registros de decisão — versionada junto ao código, com exemplos verificáveis e sem segredos. Use ao escrever ou atualizar ADR, runbook, doc de API, README, documentação de arquitetura, ou quando decisões e procedimentos precisarem ficar registrados de forma auditável.
---

# Documentação técnica

Documentação é evidência: registra decisão, procedimento e contrato para quem não estava presente. Documento desatualizado é pior que inexistente — mantenha o texto junto do código que ele descreve, atualizado na mesma mudança, e remova o que não é mais verdade.

## 1. Defina audiência e objetivo

- Separe leitores: time (README, ADR), operação (runbook), integradores (doc de API), futura manutenção (comentário de decisão).
- Cada documento responde a uma pergunta: “por que decidimos assim”, “o que fazer quando falhar”, “como integrar”, “como rodar”.
- Escreva no idioma e nível de detalhe do público real; não presuma contexto que o leitor não tem.
- Não documente o que o código/tipo/teste já declara claramente; registre o que não é observável — motivo, trade-off, consequência.

## 2. Registre decisões (ADR)

Para escolhas difíceis de reverter, registre de forma breve e datada:

- **Contexto:** problema e restrições relevantes na época.
- **Opções consideradas:** as plausíveis, com trade-offs reais — não uma justificativa da escolha já feita.
- **Decisão:** o que foi decidido e escopo de aplicação.
- **Consequências:** o que ficou melhor, o que ficou pior, dívidas assumidas.
- **Sinais de revisão:** condições que justificariam rever a decisão.

Numere sequencialmente, nunca reescreva um ADR aceito — supra-o com um novo e marque o antigo como substituído. Mantenha a ligação com `arquitetura-aplicacoes-web`, que define quando um registro é necessário.

## 3. Escreva runbooks operáveis

- Um runbook cobre um cenário de falha específico: sintoma, diagnóstico passo a passo, ação de mitigação, verificação de sucesso e escalação com contato.
- Toda ação destrutiva ou irreversível marcada com aviso e pré-condição; inclua rollback para cada mudança.
- Prefira comandos verificáveis (“rode X, espere Y”) a orientações vagas (“verifique se está íntegro”).
- Revisado após cada incidente real que o usou; registre o que faltou. Integre com os alertas e procedimentos definidos por `entrega-producao-observabilidade`.
- Sem segredos, IPs sensíveis ou dados pessoais em exemplos; use placeholders claros.

## 4. Documente APIs como contrato

- Descreva recursos, parâmetros, tipos, erros públicos, paginação, idempotência, autenticação e versionamento — o que o consumidor precisa para integrar sem ler o código.
- Exemplos executáveis com dados sintéticos, cobrindo caminho feliz e erro representativo.
- Mantenha changelog por versão com breaking changes destacadas; documento e implementação mudam no mesmo PR.
- Erros documentados devem existir de fato; valide exemplos contra a suíte de contrato conforme `testes-qualidade-web`.

## 5. Documente o repositório

- README essencial: o que é, pré-requisitos, como rodar local, como rodar testes, variáveis de ambiente obrigatórias (nomes, nunca valores) e links para ADRs e runbooks.
- Estrutura de pastas explicada apenas onde a organização não é evidente.
- Comandos copiáveis e testados; se quebrar, o README mente — trate exemplo quebrado como defeito.
- Docs vivem perto do código a que se referem; um responsável por revisão; atualização no mesmo PR da mudança correspondente.

## 6. Evite ruído e exposição

- Não crie documento “para depois preencher”; sem conteúdo real, não crie.
- Marque incerteza e pendências explicitamente (“validar com X”) em vez de afirmar.
- Nunca inclua segredos, credenciais, chaves ou dados pessoais em documentos, diagramas ou exemplos; se aparecer por engano, trate como exposição e rotacione conforme `resposta-vulnerabilidades`.
- Diagramas simples e datados; retire diagramas de arquitetura que não correspondem ao código.

## Formato de entrega

1. **Audiência e objetivo** — leitor e pergunta que o documento responde.
2. **Conteúdo** — documentos criados/atualizados e onde vivem.
3. **Verificabilidade** — exemplos testados, links para código/ADR/alertas.
4. **Manutenção** — dono, gatilho de atualização e pendências marcadas.
5. **Riscos** — informações incertas, desatualizadas ou ausentes.

Para decidir o que merece registro de decisão, use `arquitetura-aplicacoes-web`; para procedimentos de operação e alertas, `entrega-producao-observabilidade`; para validação de exemplos e contratos, `testes-qualidade-web`.
