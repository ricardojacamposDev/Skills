---
name: recursos-ia-generativa
description: Desenvolve e revisa funcionalidades com IA generativa e LLMs — prompts, RAG, agentes, guardrails, prompt injection, tratamento de saída, avaliações, custo/latência e governança de dados. Use ao construir chatbot, copiloto, geração de conteúdo, busca semântica, agente ou qualquer integração com modelo de linguagem, mesmo que o pedido seja apenas funcional.
---

# Recursos de IA generativa

Trate o modelo como um componente probabilístico dentro da aplicação, não como fonte de verdade ou fronteira de segurança. O sistema continua responsável por validar entradas, restringir ações, verificar saídas e proteger dados; confiança no modelo não substitui controles no código.

## 1. Entenda a tarefa e o risco

- Distinga uso tolerante a erro (rascunho, sugestão) de uso sensível (decisão, dado ao usuário final, execução de ação); a criticidade define quanta validação é necessária.
- Registre o que a funcionalidade promete ao usuário e o que não faz; não deixe a interface implicar garantia que o modelo não tem.
- Identifique dados que entram no prompt, quem pode influenciá-los e o que acontece com a saída (exibida, armazenada, executada, usada em decisão).
- Modele ameaças com `seguranca-aplicacoes` quando houver ações, dados pessoais ou conteúdo de terceiros no fluxo.

## 2. Projete entradas e contexto

- Considere prompt injection direto (usuário) e indireto (conteúdo buscado em RAG, páginas, arquivos, mensagens, código): trate todo conteúdo externo como dado, nunca como instrução.
- Não dependa de instruções de sistema como controle de segurança; aplique validação e autorização no código fora do modelo.
- Limite tamanho do prompt, do contexto e dos documentos ingeridos; controle custo e latência com `eficiencia-computacional`.
- Não envie dados pessoais desnecessários ao provedor; avalie retenção, treinamento e região conforme `privacidade-dados`.
- Para RAG, registre proveniência dos documentos e mostre fontes quando a resposta afirmar fatos.

## 3. Controle saídas antes do uso

- Valide saída por schema (JSON, tipos, limites) antes de processar; rejeite com tratamento de erro, não tente "consertar" silenciosamente.
- Nunca execute saída do modelo (código, SQL, comandos, caminhos, URLs) sem validação explícita e contexto de menor privilégio; prefira saída estruturada que seleciona entre ações pré-aprovadas.
- Aplique encoding no contexto de destino (HTML, markdown, atributo) — saída de modelo também é vetor de XSS.
- Para conteúdo gerado ao usuário final, defina moderação e política de conteúdo proporcionais; registre decisões de bloqueio.
- Detecte e trate respostas vazias, recusas, alucinação de fontes/citações e loops; comunique incerteza em vez de inventar certeza.

## 4. Conceda ferramentas e ações com parcimônia

- Exponha ferramentas por permitlist, com escopo mínimo, limites de taxa e de custo por usuário/tenant.
- Autorização é decisão do sistema, não do modelo: verifique permissão no servidor antes de executar qualquer ação pedida via agente, inclusive ações entre tenants.
- Ações irreversíveis (pagamento, exclusão, envio em massa) exigem confirmação explícita do usuário e registro auditável.
- Limite autonomia: orçamento de passos, tempo e chamadas por execução; monitore abusos e consumo anormal.

## 5. Avalie e monitore

- Monte conjunto de avaliação versionado com casos de uso e casos adversariais sintéticos (prompt injection, tentativa de extração de instruções, entrada fora de escopo); rode como teste de regressão conforme `testes-qualidade-web`.
- Meça qualidade por tarefa (fidelidade a fontes, taxa de formato válido, recusa correta) e não só satisfação subjetiva; compare mudanças de prompt/modelo em condições equivalentes.
- Registre versão do modelo, prompt e parâmetros por execução para reproduzir diagnóstico.
- Monitore custo, latência, taxa de erro e bloqueios; logs sem dados pessoais nem conteúdo sensível de prompts, conforme `privacidade-dados`.

## 6. Trate dados de treinamento e fine-tuning

- Para ajuste fino ou embeddings: minimize dados, documente proveniência e base legal, garanta direitos de exclusão e evite dados de produção reais sem autorização.
- Dados sintéticos ou anonimizados em experimentos; anonimização precisa resistir à reidentificação.
- Não use dados de usuários de um tenant para melhorar serviço de outro sem base válida.

## Formato de entrega

1. **Objetivo e criticidade** — tarefa, tolerância a erro e promessa ao usuário.
2. **Fluxo de dados** — o que entra no prompt, influenciáveis e destinos da saída.
3. **Controles** — validação de entrada/saída, ferramentas, autorização, limites e moderação.
4. **Avaliação** — conjunto, casos adversariais e resultados comparativos.
5. **Operação** — custos, latência, monitoramento e versionamento de prompt/modelo.
6. **Riscos residuais** — incertezas e limites do modelo no contexto.

Para modelagem de ameaças e controles de acesso, use `seguranca-aplicacoes`; para dados pessoais, `privacidade-dados`; para automatizar as avaliações, `testes-qualidade-web`.
