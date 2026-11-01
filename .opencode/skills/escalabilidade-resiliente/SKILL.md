---
name: escalabilidade-resiliente
description: Projeta e valida escalabilidade, capacidade, resiliência e desempenho distribuído com SLOs, testes de carga, backpressure, filas, caches, particionamento e autoscaling. Use sempre que o usuário mencionar crescimento de tráfego ou dados, gargalos, alta disponibilidade, latência de cauda, picos, capacity planning, load testing ou escalonamento de APIs, workers e bancos de dados.
---

# Escalabilidade resiliente

Escale a partir de carga, SLOs e gargalos medidos. Mais instâncias não corrigem contenção, trabalho sem limites ou dependências saturadas; distribuir um sistema também cria novos modos de falha e custo.

## 1. Defina carga e critérios de sucesso

Registre:

- requisições/eventos por segundo, concorrência, tamanho de payload e distribuição por tenant;
- volume e taxa de crescimento de dados, leitura/escrita e cardinalidade;
- tráfego médio, pico, rajadas e padrões sazonais;
- SLOs de disponibilidade e latência p50/p95/p99, throughput e freshness;
- RTO/RPO quando recuperação estiver no escopo;
- limites de custo e recursos.

Separe premissas de métricas observadas. Use unidades consistentes e, quando útil, relações de capacidade como Lei de Little (`L = λW`) para checar plausibilidade.

## 2. Meça e encontre o recurso limitante

Construa uma linha de base e um modelo simples de capacidade por instância/pod/nó. Observe CPU, memória, conexões, I/O, locks, filas, largura de banda, limites de quotas e dependências externas.

Teste uma hipótese por vez. Identifique o primeiro recurso que satura e o efeito sobre latência de cauda, erros e filas; média de latência sozinha esconde degradação.

## 3. Escolha a estratégia mínima adequada

### Aplicação e tráfego

- Prefira componentes stateless quando isso simplificar escala horizontal.
- Imponha timeouts, limites de payload, concorrência e filas; rejeite ou degrade carga antes de colapsar.
- Use backpressure e load shedding com prioridade explícita para operações críticas.
- Faça retries somente quando seguros, com orçamento, backoff exponencial e jitter; exija idempotência ou deduplicação para operações repetíveis.
- Aplique rate limiting e quotas por dimensão apropriada, incluindo tenant, sem confundir fairness com defesa completa contra abuso.

### Cache e dados

- Introduza cache apenas com semântica de invalidação, TTL, limites e isolamento entre tenants definidos.
- Previna cache stampede e avalie o comportamento em cache frio.
- Otimize consultas e índices antes de particionar prematuramente.
- Para particionamento, analise distribuição, hotspots, consultas transversais, rebalanceamento e crescimento de cardinalidade.
- Use paginação com limites e streaming/lotes limitados em vez de carregar coleções inteiras.

### Assíncrono e falhas

- Use filas para desacoplar picos somente com limites, visibilidade de atraso e política para poison messages/DLQ.
- Defina entrega at-least-once/at-most-once realista e projete consumidores idempotentes.
- Considere circuit breakers, bulkheads e degradação controlada para isolar dependências.
- Não deixe autoscaling depender apenas de CPU quando fila, latência ou concorrência representarem melhor a pressão; respeite limites downstream.

## 4. Valide carga e falha

Execute testes de carga ou injeção de falhas somente em ambiente controlado, após confirmar autorização, e com escopo, limites de taxa, monitoramento e critérios de parada definidos. Simule dependências de terceiros, salvo autorização específica; sem essas condições, entregue apenas o plano de teste.

Crie testes com dados sintéticos e distribuição representativa:

1. carga esperada;
2. pico previsto e rajada;
3. aumento progressivo até o limite;
4. soak test para vazamentos e degradação;
5. falha ou lentidão de dependência e perda parcial de capacidade.

Meça throughput sustentável, saturação, p95/p99, erros, filas, recuperação e custo por unidade de trabalho. Teste o sistema completo ou declare claramente os componentes simulados.

## 5. Planeje implantação e evolução

- Faça rollout progressivo, com métricas, limites automáticos e rollback compatível.
- Garanta migrações e mudanças de schema compatíveis com versões simultâneas.
- Documente capacidade máxima observada, headroom e gatilhos para a próxima ação.
- Evite multi-região, sharding ou malha complexa sem requisito mensurável que justifique o custo operacional.

## Formato de entrega

1. **Carga e SLOs** — observações, premissas e cenários.
2. **Modelo de capacidade** — gargalo, limite e headroom.
3. **Mudanças propostas ou realizadas** — impacto, risco e trade-offs.
4. **Plano e resultado de testes** — carga, falhas, latência de cauda e recuperação.
5. **Rollout e observabilidade** — métricas, alertas e rollback.
6. **Custo e riscos residuais**.

Antes de otimizar o caminho quente, use `eficiencia-computacional`; se a escala ampliar risco de abuso ou vazamento entre tenants, inclua `seguranca-aplicacoes`.
