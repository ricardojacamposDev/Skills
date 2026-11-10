---
name: testes-e2e
description: Projeta, implementa e mantém testes end-to-end (ponta a ponta) de aplicações web em navegador real, cobrindo fluxos críticos de usuário, estados, dados, permissões e regressões. Use ao criar ou corrigir testes E2E, validar jornadas completas, estabilizar suíte instável, configurar execução em CI ou reproduzir falhas de fluxo; combine com testes-qualidade-web para seleção de camadas e com seguranca-aplicacoes para casos negativos.
---

# Testes end-to-end (E2E)

Teste poucos fluxos críticos completos, em ambiente reproduzível e com dados controlados. E2E é a camada mais cara e lenta da pirâmide de testes: ela valida a integração real entre interface, rede, autenticação e persistência, mas não substitui testes unitários e de integração nem justifica cobrir detalhes internos.

## 1. Defina o escopo do fluxo

- Liste jornadas que, se quebrarem, impedem uso ou receita: autenticação, cadastro, pagamento, checkout, busca, criação/edição/exclusão de recurso principal, permissões e recuperação de senha.
- Para cada fluxo, escreva o resultado observável esperado, incluindo estados intermediários, mensagens, redirecionamentos e persistência.
- Inclua casos negativos de alto impacto: credenciais inválidas, sessão expirada, permissão negada, dados inválidos, conflito de concorrência e indisponibilidade parcial.
- Evite transformar toda regra de negócio em E2E. Se a falha pode ser detectada em camada mais baixa, teste lá e mantenha o E2E no fluxo completo.
- Defina critérios de entrada e saída da suíte: quais fluxos são obrigatórios, quais são opcionais e qual tempo máximo aceitável.

## 2. Prepare ambiente reproduzível

- Use ambiente local ou de teste controlado, com banco de dados e serviços de apoio isolados e recriáveis.
- Prefira dados sintéticos e contas dedicadas; nunca use dados pessoais reais, credenciais de produção ou segredos em fixtures.
- Garanta que o app suba de forma determinística (migrações, seeds e variáveis de ambiente documentadas) antes de executar a suíte.
- Fixe versões do navegador e do framework de teste; registre viewport, locale, fuso horário e permissões usados.
- Isole estado entre execuções: limpe banco, storage, cookies, cache e arquivos gerados ao final de cada teste ou da suíte.
- Documente como rodar localmente e em CI, incluindo pré-requisitos e tempo esperado.

## 3. Projete casos estáveis

- Cada teste deve preparar e limpar seu próprio estado; não dependa de ordem, de dados criados por outro teste ou de estado residual.
- Use um único ator/usuário por teste, salvo quando o cenário exigir interação entre papéis; nesse caso, crie e limpe todos os atores.
- Separe autenticação reutilizável (storage state/sessão salva) da criação de dados específicos do cenário.
- Evite aleatoriedade não controlada; se necessário, use seed fixa e registre-a para reproduzir falhas.
- Priorize fluxos de leitura para smoke tests e fluxos de escrita para regressão; marque testes lentos ou instáveis para execução separada.
- Não combine muitas asserções não relacionadas em um mesmo teste; falha deve apontar causa clara.

## 4. Escreva testes robustos

- Use seletores semânticos e acessíveis (papel, nome acessível, texto visível, rótulo) antes de seletores internos; recorra a atributos de teste apenas quando não houver alternativa estável.
- Aguarde condições observáveis (elemento visível/habilitado, resposta de rede, estado da URL, persistência) em vez de pausas fixas.
- Interaja como usuário: clique, digite, navegue por teclado quando o fluxo exigir; evite manipular estado interno diretamente, salvo em setup.
- Capture evidências em falha: screenshot, vídeo curto, trace e logs de rede/console com segredos e dados pessoais mascarados.
- Teste responsividade em viewports relevantes; não assuma apenas desktop.
- Para formulários, valide erros de campo, preservação de valores, submissão duplicada e estados de carregamento.
- Para autenticação e autorização, teste login, logout, expiração de sessão, acesso negado e isolamento entre usuários/tenants.
- Mantenha page objects ou helpers apenas quando reduzirem duplicação real; não crie abstrações que escondam a intenção do teste.

## 5. Execute, diagnostique e mantenha

1. Rode primeiro o teste mais focado disponível; amplie a suíte apenas quando a superfície afetada justificar.
2. Reproduza a falha localmente antes de alterar código ou teste; não enfraqueça asserções para "fazer passar".
3. Classifique a causa: defeito de produto, fragilidade do teste, problema de ambiente ou flakiness.
4. Se o teste estiver instável, investigue sincronização, dados compartilhados, animações, rede e ordem de execução; registre a causa e o plano de correção.
5. Corrija a causa raiz e adicione regressão proporcional ao defeito.
6. Rode testes relacionados e, quando justificado, a suíte E2E completa; reporte falhas preexistentes separadamente.
7. Revise periodicamente testes lentos, duplicados ou obsoletos; remova o que não agrega valor.

Não declare validação bem-sucedida se testes foram ignorados, instáveis ou não executados.

## 6. Integre a CI com controle de custo

- Execute smoke E2E em todo pull request e a suíte completa em pipeline noturno ou antes de release, conforme tempo e custo.
- Paralelize por arquivo/fluxo quando o framework suportar, mantendo isolamento de dados.
- Use retries apenas para absorver instabilidade transitória de infraestrutura; retries não corrigem defeito de produto e devem ser monitorados.
- Defina limites de tempo e falha rápida para não bloquear a equipe com suíte lenta.
- Armazene artefatos de falha por tempo limitado e com acesso controlado; revise conteúdo antes de compartilhar.
- Meça tempo, taxa de sucesso e flakiness; use métricas para decidir quais testes manter, otimizar ou remover.

## 7. Segurança, privacidade e dados

- Use contas e dados sintéticos; masque tokens, cookies, cabeçalhos de autorização e informação pessoal em logs, traces e screenshots.
- Não execute E2E contra produção ou sistemas de terceiros sem autorização explícita e escopo definido.
- Em cenários de segurança, combine com `seguranca-aplicacoes` e `testes-vulnerabilidades`; E2E valida fluxo, não substitui testes negativos de autorização e isolamento.
- Revise screenshots e vídeos antes de anexá-los a relatórios ou sistemas de rastreamento.

## Formato de entrega

1. **Risco e escopo** — jornadas cobertas, premissas e exclusões.
2. **Ambiente** — como o app e os dados são preparados e limpos.
3. **Estratégia** — seletores, esperas, paralelismo e evidências de falha.
4. **Mudanças** — testes, fixtures e helpers adicionados ou ajustados.
5. **Execução** — comandos, resultado, tempo e falhas/limitações.
6. **Risco residual** — fluxos ou estados ainda não validados.

Para seleção de camadas de teste, use `testes-qualidade-web`; para interfaces e acessibilidade, `interface-ux-acessibilidade`; para desempenho de páginas e fluxos, `eficiencia-computacional`; para segurança de fluxos e autorização, `seguranca-aplicacoes`.