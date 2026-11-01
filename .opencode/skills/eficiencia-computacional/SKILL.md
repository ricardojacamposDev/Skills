---
name: eficiencia-computacional
description: Otimiza desempenho e economia computacional — CPU, memória, alocações, I/O, rede, energia e custo de nuvem — com profiling e benchmarks antes e depois. Use sempre que o usuário mencionar lentidão, performance, complexidade, uso de recursos, custo por requisição, eficiência energética ou otimização de código e infraestrutura, mesmo sem pedir explicitamente uma análise de desempenho.
---

# Eficiência computacional

Reduza custo e consumo de recursos sem trocar um problema mensurável por uma otimização prematura. Preserve corretude, segurança, privacidade e legibilidade; uma melhoria só conta quando é medida em carga representativa.

## Fluxo de trabalho

1. **Delimite o objetivo**
   - Identifique operação, ambiente, versão e carga representativa.
   - Registre restrições de latência, throughput, memória, custo e compatibilidade.
   - Converta o objetivo em uma métrica: p95/p99, operações/s, CPU-s/operação, bytes/operação ou custo por mil operações.

2. **Estabeleça a linha de base**
   - Reutilize métricas e traces existentes antes de criar instrumentação nova.
   - Meça a versão atual com dados e configuração equivalentes aos de produção, sem dados pessoais reais.
   - Faça repetições suficientes para observar variância, aquecimento, cache e ruído.
   - Não declare gargalo apenas por inspeção visual do código.

3. **Formule e ordene hipóteses**
   - Relacione sintoma, evidência e hipótese.
   - Priorize complexidade algorítmica, trabalho redundante, chamadas N+1, I/O serial, alocações, serialização e transferência excessiva antes de micro-otimizações.
   - Estime impacto, risco e esforço; prefira a menor mudança capaz de testar a hipótese.

4. **Implemente uma mudança por experimento**
   - Mantenha comportamento observável e contratos estáveis, salvo mudança solicitada.
   - Ao introduzir cache, paralelismo ou processamento em lote, trate invalidação, limites, concorrência, backpressure e isolamento entre tenants.
   - Evite caches sem limite, pools sem teto e buffers que apenas desloquem o problema para memória.

5. **Valide o resultado**
   - Execute testes funcionais e de concorrência relevantes.
   - Compare antes/depois na mesma condição e informe mediana, dispersão e tamanho da amostra quando disponíveis.
   - Verifique se a melhoria local não piorou latência de cauda, memória, custo total ou outra etapa.
   - Reverta ou descarte otimizações sem ganho relevante.

## Atalhos de diagnóstico

- **CPU alta:** procure hotspots, complexidade superlinear, expressões regulares patológicas, compressão e serialização repetidas.
- **Memória alta:** examine retenção, cardinalidade, alocações temporárias, caches e carregamento integral de coleções.
- **Latência alta:** decomponha tempo de fila, CPU, I/O, rede e dependências; não use apenas a média.
- **Custo alto:** normalize por unidade de trabalho e considere instâncias ociosas, transferência, logs, armazenamento e retries, não só preço da máquina.
- **Throughput baixo:** verifique contenção, locks, conexões, lotes, limites de concorrência e saturação downstream.

## Economia durante a investigação

Comece com evidências já disponíveis e limite o escopo ao caminho quente. Execute profiles e testes caros apenas quando puderem confirmar ou refutar uma hipótese. Não repita suítes completas após mudanças irrelevantes, mas rode todos os testes exigidos pelo impacto final.

## Formato de entrega

Apresente, de forma concisa:

1. **Objetivo e linha de base** — ambiente, carga, métricas e limitações.
2. **Gargalo confirmado** — evidência e hipóteses descartadas.
3. **Mudança realizada ou proposta** — arquivos/componentes e por quê.
4. **Resultado comparativo** — antes/depois, unidades, variância e trade-offs.
5. **Validação** — testes executados e riscos remanescentes.
6. **Próximo passo** — somente se houver ganho esperado proporcional ao esforço.

Se não houver dados para medir, entregue um plano mínimo de instrumentação e não invente percentuais de melhoria. Para gargalos de capacidade, filas ou autoscaling, complemente com `escalabilidade-resiliente`.
