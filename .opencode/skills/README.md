# Manual de uso das skills

Este manual ajuda a escolher e combinar as skills disponíveis em `.opencode/skills`. Elas orientam o agente sobre como investigar, implementar e validar tarefas; não substituem os requisitos do projeto, a autorização para testar sistemas nem a revisão humana.

## Como pedir o uso de uma skill

Descreva o objetivo, o contexto e o resultado esperado. Para direcionar o trabalho, mencione a skill pelo nome no pedido. Se o seu cliente oferecer seleção de skills ou comandos, também é possível selecioná-la por lá.

Exemplo:

> Use `seguranca-aplicacoes` para revisar o fluxo de autorização desta API. Analise o código e os testes, corrija os problemas confirmados e valide que usuários de outros tenants continuam sem acesso.

O nome da skill também pode ser combinado com uma tarefa concreta. Em vez de pedir apenas “use a skill”, informe o componente envolvido, os limites conhecidos e se deseja análise, plano ou implementação.

## Índice rápido

| Necessidade | Skill | Use quando |
|---|---|---|
| Analisar controles de segurança ou modelar ameaças | [`seguranca-aplicacoes`](./seguranca-aplicacoes/SKILL.md) | A tarefa envolve autenticação, autorização, entradas, segredos, integrações ou revisão de código segura. |
| Pesquisar ou validar uma vulnerabilidade | [`pesquisa-vulnerabilidades`](./pesquisa-vulnerabilidades/SKILL.md) | É preciso investigar uma CVE, advisory, finding ou possível caminho vulnerável. |
| Corrigir ou responder a um alerta de vulnerabilidade | [`resposta-vulnerabilidades`](./resposta-vulnerabilidades/SKILL.md) | É preciso priorizar, conter, corrigir e comprovar a correção de um finding. |
| Executar testes de vulnerabilidade | [`testes-vulnerabilidades`](./testes-vulnerabilidades/SKILL.md) | É pedido teste de vulnerabilidades, scan de segurança, checagem de headers/cookies ou validação de segurança antes de release. |
| Comandar resposta a incidente ou postmortem | [`resposta-incidentes`](./resposta-incidentes/SKILL.md) | Há interrupção, vazamento ou suspeita de comprometimento em andamento, ou preparo de playbook, escalonamento e postmortem. |
| Prevenir riscos na cadeia de suprimentos | [`supply-chain-construtor`](./supply-chain-construtor/SKILL.md) | A tarefa envolve adicionar/atualizar dependências, pipeline de build, publicação/consumo de artefatos, pinning, SBOM ou proveniência. |
| Tratar dados pessoais e prevenir exposição | [`privacidade-dados`](./privacidade-dados/SKILL.md) | A tarefa coleta, armazena, compartilha, registra ou exclui dados pessoais. |
| Construir funcionalidade com IA generativa | [`recursos-ia-generativa`](./recursos-ia-generativa/SKILL.md) | A tarefa integra LLM, chatbot, copiloto, RAG ou agente — prompts, guardrails, avaliações e governança de dados. |
| Otimizar desempenho com segurança | [`eficiencia-computacional`](./eficiencia-computacional/SKILL.md) | Há lentidão, consumo excessivo, custo ou necessidade de medir uma otimização. |
| Dimensionar serviços e tratar picos | [`escalabilidade-resiliente`](./escalabilidade-resiliente/SKILL.md) | Há crescimento de tráfego/dados, gargalos, filas, capacidade ou requisitos de resiliência. |
| Definir limites e contratos de um sistema web | [`arquitetura-aplicacoes-web`](./arquitetura-aplicacoes-web/SKILL.md) | A tarefa envolve arquitetura, APIs, integrações, persistência ou migrações. |
| Registrar decisões, runbooks e documentação de API | [`documentacao-tecnica`](./documentacao-tecnica/SKILL.md) | É preciso escrever ADR, runbook, doc de API, README ou manter documentação verificável junto ao código. |
| Reformar código legado com segurança | [`codigo-legado-modernizacao`](./codigo-legado-modernizacao/SKILL.md) | A tarefa mexe em código antigo ou sem testes, ou migra módulo/sistema em produção de forma gradual. |
| Construir ou melhorar uma interface acessível | [`interface-ux-acessibilidade`](./interface-ux-acessibilidade/SKILL.md) | A tarefa altera fluxos, componentes, responsividade ou acessibilidade da UI. |
| Criar ou validar testes web | [`testes-qualidade-web`](./testes-qualidade-web/SKILL.md) | É necessário testar fluxos, contratos, regressões, acessibilidade ou comportamento visual. |
| Preparar release e observabilidade | [`entrega-producao-observabilidade`](./entrega-producao-observabilidade/SKILL.md) | A tarefa envolve CI/CD, deploy, migrações, métricas, alertas ou rollback. |

## Escolha pelo objetivo

### Segurança de aplicações

Use `seguranca-aplicacoes` para revisar ou implementar controles no código e na arquitetura. A análise deve relacionar evidência, caminho de abuso e impacto; uma recomendação de hardening, por si só, não deve ser apresentada como vulnerabilidade confirmada.

Exemplos:

- “Use `seguranca-aplicacoes` para modelar ameaças antes de implementar o upload de arquivos.”
- “Revise a autorização dos endpoints alterados, corrija falhas comprovadas e acrescente testes negativos.”

### Pesquisa e resposta a vulnerabilidades

Escolha `pesquisa-vulnerabilidades` para determinar se um alerta é aplicável e alcançável; use `resposta-vulnerabilidades` para priorizar e executar a correção. Combine-as quando o finding ainda não foi confirmado:

Para produzir evidência executável, use `testes-vulnerabilidades`: a bateria estática serve para qualquer repositório; as checagens HTTP e os casos dinâmicos exigem ambiente controlado, autorização e dados sintéticos. Um resultado da bateria é sempre um candidato a achado, a confirmar com `seguranca-aplicacoes`.

1. Pesquise versões afetadas, artefatos e evidências.
2. Corrija ou mitigue a causa raiz, sem atualizações indiscriminadas.
3. Teste a regressão e confirme a versão no artefato final.
4. Trate o deploy como etapa separada: “código corrigido” não significa que a produção já está corrigida.

Exemplos:

- “Use `pesquisa-vulnerabilidades` para avaliar se esta CVE afeta a versão registrada no lockfile. Faça apenas análise passiva.”
- “Use `resposta-vulnerabilidades` para corrigir o alerta e comprovar a correção com testes.”
- “Use `testes-vulnerabilidades` para rodar a bateria estática no repositório e checagens HTTP no ambiente de staging; triar os achados e implementar os casos dinâmicos aplicáveis.”

### Privacidade e proteção contra vazamentos

Use `privacidade-dados` para mapear finalidade, acesso, retenção, compartilhamento e exclusão de dados pessoais. Para controles de segurança técnica, combine com `seguranca-aplicacoes`.

Ao investigar ou testar:

- prefira dados sintéticos ou anonimizados;
- não inclua tokens, credenciais, dados pessoais ou payloads sensíveis em logs, traces, prompts ou relatórios;
- não copie um segredo encontrado para a resposta; indique a localização e recomende o processo autorizado de contenção e rotação;
- não presuma base legal ou política organizacional: registre a lacuna e peça validação aos responsáveis quando necessário.

Exemplo:

> Use `privacidade-dados` para revisar os eventos de analytics, reduzir os dados coletados e verificar que logs e testes não expõem dados pessoais.

### Inteligência artificial generativa

Use `recursos-ia-generativa` para integrar modelos de linguagem tratando o modelo como componente probabilístico: entradas e saídas validadas no código, ferramentas por permitlist, autorização decidida pelo sistema (nunca pelo modelo) e conjunto de avaliação com casos adversariais sintéticos. Combine com `privacidade-dados` para o que vai ao provedor e com `seguranca-aplicacoes` quando houver ações ou conteúdo de terceiros no fluxo.

Exemplo:

> Use `recursos-ia-generativa` para revisar o copiloto que lê documentos do tenant: avalie prompt injection indireto, autorização das ferramentas expostas e monte um conjunto de avaliação com casos adversariais.

### Desempenho e escala

Use `eficiencia-computacional` para localizar e medir um gargalo. Use `escalabilidade-resiliente` quando a questão for capacidade, picos, filas, dependências saturadas ou recuperação.

Uma sequência comum:

1. Defina carga, métrica e linha de base.
2. Identifique o gargalo com evidência.
3. Faça uma mudança por vez e compare resultados equivalentes.
4. Valide limites, autorização, concorrência e isolamento entre tenants.

Não afrouxe validação, autenticação, autorização, limites ou auditoria para obter desempenho. Testes de carga ou falha devem ter ambiente, escopo, autorização e critérios de parada definidos.

### Arquitetura, interface e testes

- Use `arquitetura-aplicacoes-web` para requisitos, contratos, persistência e trade-offs estruturais.
- Use `documentacao-tecnica` para registrar decisões (ADR), runbooks e contratos de API junto ao código, atualizados na mesma mudança.
- Use `codigo-legado-modernizacao` para reformar módulos antigos: testes de caracterização antes, passos pequenos e strangler fig — nunca reescrita total de uma vez.
- Use `interface-ux-acessibilidade` para fluxos e componentes de interface; complemente com `testes-qualidade-web` para automatizar os fluxos relevantes.
- Use `testes-qualidade-web` para selecionar a camada de teste adequada e evitar regressões. Testes de segurança devem incluir casos negativos, como acesso negado e isolamento entre usuários/tenants.

### Produção e operação

Use `entrega-producao-observabilidade` para planejar build, migração, rollout, smoke tests, monitoramento e rollback. Combine com `resposta-vulnerabilidades` quando a entrega contiver uma correção de segurança. Não execute mudanças em produção, testes intrusivos ou testes de carga sem autorização explícita e escopo adequado.

Quando algo já quebrou, use `resposta-incidentes` para comandar o evento: papéis, comunicação com cadência, contenção reversível e postmortem sem culpabilização. Para reduzir a chance de o problema entrar pela porta, use `supply-chain-construtor`: pinning de dependências, builds confiáveis, integridade/proveniência de artefatos e SBOM por build.

## Combinações frequentes

| Trabalho | Sequência sugerida |
|---|---|
| Investigar e corrigir uma CVE | `pesquisa-vulnerabilidades` → `resposta-vulnerabilidades` → `testes-qualidade-web` → `entrega-producao-observabilidade` |
| Validar segurança antes de release | `testes-vulnerabilidades` (bateria + casos dinâmicos) → triagem com `seguranca-aplicacoes` → correção com `resposta-vulnerabilidades` |
| Criar uma funcionalidade que trata dados pessoais | `arquitetura-aplicacoes-web` → `privacidade-dados` + `seguranca-aplicacoes` → `testes-qualidade-web` → `entrega-producao-observabilidade` |
| Otimizar um endpoint | `eficiencia-computacional` → `seguranca-aplicacoes` quando houver mudanças em controles ou dados → `testes-qualidade-web` |
| Preparar serviço para aumento de tráfego | `escalabilidade-resiliente` → `eficiencia-computacional` para o caminho quente → `entrega-producao-observabilidade` |
| Melhorar um fluxo de interface | `interface-ux-acessibilidade` → `testes-qualidade-web` |
| Construir feature com IA generativa | `arquitetura-aplicacoes-web` → `recursos-ia-generativa` + `privacidade-dados` → `testes-qualidade-web` (avaliações) → `entrega-producao-observabilidade` |
| Responder a incidente | `resposta-incidentes` → `resposta-vulnerabilidades` (finding de segurança) → `entrega-producao-observabilidade` (recuperação e alertas) |
| Modernizar módulo legado | `codigo-legado-modernizacao` → `testes-qualidade-web` (caracterização) → `documentacao-tecnica` (ADRs) → `entrega-producao-observabilidade` |
| Endurecer pipeline e dependências | `supply-chain-construtor` → `testes-vulnerabilidades` (bateria) → `resposta-vulnerabilidades` (quando houver alerta) |

As combinações são sugestões, não uma sequência obrigatória. Se a tarefa for pequena, use apenas a skill necessária.

## Segurança e limites de atuação

- **Defina o escopo:** informe repositório, componente e ambiente envolvidos.
- **Testes ativos exigem autorização:** sem autorização explícita e limites claros, restrinja a análise ao código, à documentação e a testes locais não intrusivos.
- **Pare diante de efeitos inesperados:** interrompa testes se houver instabilidade, dados fora do escopo ou impacto não previsto.
- **Não exponha dados:** use exemplos sintéticos e remova segredos e dados pessoais de evidências compartilhadas.
- **Relate incerteza:** diferencie hipótese, vulnerabilidade confirmada, falso positivo e resultado inconclusivo; informe limitações e testes não executados.
- **Valide antes de concluir:** peça evidências observáveis, como testes, análise do artefato ou métricas; não declare sucesso sem execução.

## Modelo de pedido

Adapte este formato ao trabalho:

> Use `[nome-da-skill]` para `[objetivo]` em `[componente/escopo]`. Quero `[análise/plano/implementação]`. Restrições: `[ambiente, autorização, compatibilidade, dados de teste]`. Valide com `[testes ou evidências esperadas]` e informe limitações e riscos residuais. Não exponha segredos ou dados pessoais.

## Comando para considerar todas as skills

Copie o comando abaixo e substitua os campos entre colchetes. Ele pede ao agente que consulte todas as skills disponíveis, selecione as relevantes e combine suas orientações sem aplicar etapas que não façam sentido para a tarefa.

> Considere todas as skills deste repositório antes de trabalhar: `arquitetura-aplicacoes-web`, `codigo-legado-modernizacao`, `documentacao-tecnica`, `eficiencia-computacional`, `entrega-producao-observabilidade`, `escalabilidade-resiliente`, `interface-ux-acessibilidade`, `pesquisa-vulnerabilidades`, `privacidade-dados`, `recursos-ia-generativa`, `resposta-incidentes`, `resposta-vulnerabilidades`, `seguranca-aplicacoes`, `supply-chain-construtor`, `testes-qualidade-web` e `testes-vulnerabilidades`. Minha tarefa é: `[descreva o objetivo e o escopo]`. Identifique quais skills se aplicam e use suas orientações em conjunto; explique brevemente qualquer skill não aplicável, sem forçar etapas irrelevantes. Preserve segurança, privacidade e corretude; não exponha segredos ou dados pessoais. Não faça testes ativos ou mudanças em produção sem autorização explícita. Implemente `[ou: analise/proponha um plano para]` a solução e valide com `[testes/evidências esperadas]`. Informe mudanças, resultados, limitações e riscos residuais.
