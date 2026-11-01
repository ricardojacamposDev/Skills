---
name: testes-qualidade-web
description: Define, implementa e executa testes para aplicações web — unitários, integração, API, ponta a ponta, acessibilidade e regressão visual. Use ao criar ou corrigir testes, investigar falhas, validar fluxos críticos, prevenir regressões ou preparar um app/site para produção.
---

# Testes e qualidade web

Construa confiança verificável no comportamento do produto. Escolha testes pela falha que precisam detectar, não pela quantidade de casos ou cobertura isolada. Antes de adicionar ferramentas, descubra os comandos, frameworks, fixtures e convenções já adotados pelo projeto.

## 1. Defina o risco e o comportamento esperado

- Identifique fluxos críticos, usuários, permissões, integrações e estados de erro.
- Transforme requisitos em resultados observáveis, incluindo limites e casos negativos.
- Priorize caminhos de pagamento, autenticação, autorização, dados persistidos, formulários e operações irreversíveis.
- Separe comportamento confirmado de suposições. Quando requisito ambíguo alterar o resultado esperado, peça esclarecimento.

## 2. Escolha a camada adequada

- **Unitário:** regras determinísticas, transformações, validações e estados isolados.
- **Integração:** interação real entre módulos, banco de dados, filas ou serviços; prefira dependências locais controladas.
- **API/contrato:** formatos, status, autenticação, autorização, compatibilidade e erros públicos.
- **Ponta a ponta:** poucos fluxos críticos completos em navegador e ambiente reproduzível.
- **Acessibilidade:** verificações automatizadas complementadas por teclado, foco e semântica.
- **Visual:** mudanças de layout e componentes onde comparação de screenshots reduz risco; controle viewport, fontes, animações e dados.

Não teste detalhes internos que possam mudar sem alterar o comportamento. Evite substituir por mocks a mesma integração cujo contrato se quer validar.

## 3. Projete casos confiáveis

- Inclua caminho feliz, entradas inválidas, estados vazios/carregando/erro, limites e permissões negadas.
- Use dados sintéticos e independentes; cada teste deve preparar e limpar seu próprio estado.
- Elimine dependência de ordem, relógio real, rede instável, serviços externos e dados compartilhados.
- Use seletores semânticos acessíveis e conteúdo visível; recorra a seletores internos apenas quando necessário.
- Aguarde condições observáveis, não pausas fixas. Garanta limpeza de listeners, timers e recursos.
- Para aleatoriedade, preserve seed e evidência que permita reproduzir a falha.

## 4. Execute e diagnostique

1. Leia scripts do projeto e rode primeiro o teste mais focado disponível.
2. Reproduza a falha sem enfraquecer asserções ou remover cobertura relevante.
3. Examine logs, traces, screenshots e estado de rede sem expor segredos ou dados pessoais.
4. Corrija a causa e adicione regressão proporcional ao defeito.
5. Rode testes relacionados e, quando a superfície afetada justificar, a suíte mais ampla.

Reporte falhas preexistentes separadamente. Não declare validação bem-sucedida se testes foram ignorados, instáveis ou não executados.

## 5. Considere acessibilidade e privacidade

- Combine ferramentas automatizadas com checagens manuais de teclado, foco, rótulos e mensagens de erro.
- Não trate uma pontuação automatizada como prova de conformidade.
- Use contas e dados sintéticos; masque tokens, cookies e informação pessoal em artefatos e logs.
- Em testes visuais, reveja o conteúdo dos screenshots antes de compartilhá-los ou armazená-los.

## Formato de entrega

1. **Risco e escopo** — fluxos cobertos e premissas.
2. **Estratégia** — camadas escolhidas e por quê.
3. **Mudanças** — testes e fixtures adicionados ou ajustados.
4. **Execução** — comandos, resultado e falhas/limitações.
5. **Risco residual** — comportamentos ainda não validados.

Para desempenho de páginas, complemente com `eficiencia-computacional`; para revisão específica de segurança, use `seguranca-aplicacoes`.
