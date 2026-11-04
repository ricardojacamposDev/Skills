---
name: codigo-legado-modernizacao
description: Moderniza e refatora código legado com segurança — testes de caracterização, passos pequenos, strangler fig, migração incremental de dados e contratos, sem big-bang rewrite. Use ao trabalhar em código antigo ou sem testes, migrar sistema em produção, desacoplar monólito, reduzir acoplamento estrutural ou planejar reforma gradual de módulo/sistema.
---

# Código legado e modernização

Reforme sistemas em produção mudando o comportamento apenas de propósito, com rede de segurança antes de cada passo. Código legado não é código a ser reescrito por impulso: é código que paga contas e cujos comportamentos — inclusive os aparentemente errados — podem ter consumidores.

## 1. Mapeie antes de mexer

- Identifique pontos de entrada (rotas, filas, jobs, integrações), dados lidos/escritos, dependências reais e consumidores do contrato atual.
- Distinga comportamento observado de intenção original; comentários e memórias do time são hipóteses, não verdade.
- Localize a dor concreta: risco de mudança, incidente recorrente, custo de desenvolvimento ou de operação. Reforme o que dói, não o que incomoda esteticamente.
- Registre áreas intocáveis por decisão de negócio (congeladas) e por quê.

## 2. Construa a rede de segurança primeiro

- Antes de qualquer mudança estrutural, crie **testes de caracterização** que fixam o comportamento atual, incluindo saídas que parecem bugs: eles pinam o presente, não o correto.
- Prefira golden masters em fronteiras estáveis (resposta de endpoint, arquivo gerado, mensagem de fila) a testes de detalhes internos voláteis.
- Priorize cobertura nos caminhos de maior risco e valor (pagamento, autorização, dados persistentes), conforme `testes-qualidade-web`.
- Se não for possível testar sem mudar código, faça a menor costura possível (ponto de entrada, extrator de função) e registre-a como dívida.
- Comportamento atual que não pode ser reproduzido em teste é um risco conhecido — documente, não ignore.

## 3. Refatore em passos pequenos e observáveis

- Uma mudança por commit/PR, cada uma deixando o sistema funcionando; sem “refatoração geral” misturada com ajuste funcional.
- Verifique cada passo com a rede de segurança rodando; pare e reverta no primeiro sinal de divergência não intencional.
- Melhorias espontâneas (“já que estou aqui”) só com teste próprio; caso contrário, registre como pendência.
- Melhore a estrutura ao redor do caminho que você já está mudando, não em varredura global sem objetivo.
- Meça o efeito no caminho quente quando a mudança tocar desempenho, com `eficiencia-computacional`.

## 4. Use strangler fig para substituir gradualmente

- Intercepte o fluxo em uma fachada/rota e desvie progressivamente para a nova implementação, mantendo o legado respondendo pelo resto.
- Desvie por critério controlado (rota, tenant, percentual de tráfego, tipo de recurso) com reversão rápida por flag/config, conforme `entrega-producao-observabilidade`.
- Quando dados mudam de lugar, use escrita dupla ou migração por etapas com reconciliação verificável; só corte o legado após leitura estável e consistência comprovada na nova fonte.
- Remova código legado em etapa final, separada da migração de escrita — código migrado e código removido são estados distintos.
- Versões simultâneas do contrato exigem compatibilidade nas duas direções enquanto coexistirem.

## 5. Preserve dados e contratos

- Migrações de schema compatíveis e reversíveis: expandir, migrar, validar, só então remover legado.
- Contratos públicos mudam com deprecação, aviso e prazo — nunca quebre consumidores sem comunicação e alternativa.
- Para cada etapa, defina como verificar corretude dos dados migrados (contagens, somas de controle, amostragem) e como voltar atrás.
- Não normalize dados históricos “aproveitando” a migração; correção de dado é mudança funcional com validação própria.

## 6. Controle o processo, não só o código

- Objetivo mensurável por iniciativa (ex.: “rota X fora do legado”, “estado Y com dono único”), critérios de conclusão e o que não entra no escopo.
- Progresso visível (lista de módulos/rotas migradas) para evitar reforma infinita.
- Não congele desenvolvimento de funcionalidade sem acordo: modernização caminha junto com o produto na medida do possível.
- Registre decisões estruturais relevantes como ADR, com apoio de `arquitetura-aplicacoes-web` e `documentacao-tecnica`.

## Formato de entrega

1. **Mapa e risco** — comportamentos, consumidores, áreas intocáveis e dor que motiva a reforma.
2. **Rede de segurança** — testes de caracterização criados e lacunas conhecidas.
3. **Plano incremental** — etapas, critérios de desvio/reversão e de conclusão.
4. **Execução** — mudanças realizadas, uma por passo, com validação de cada uma.
5. **Dados e contratos** — migrações, compatibilidade e verificação de corretude.
6. **Estado e pendências** — progresso, dívidas e próximo passo recomendado.

Para estratégia de testes, use `testes-qualidade-web`; para limites e decisões arquiteturais, `arquitetura-aplicacoes-web`; para rollout, reversão e monitoramento, `entrega-producao-observabilidade`.
