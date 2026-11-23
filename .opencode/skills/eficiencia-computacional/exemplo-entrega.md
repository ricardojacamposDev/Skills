# Exemplo de entrega — `eficiencia-computacional`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Objetivo e linha de base** — Reduzir o p95 de `GET /pedidos` (hoje 840 ms) para menos de 400 ms. Medido em staging com 5 mil pedidos sintéticos, 30 repetições; variância baixa (±6%).

2. **Gargalo confirmado** — Profiling mostra 71% do tempo em 1 consulta por item (N+1). Hipótese de serialização descartada: 4% do tempo.

3. **Mudança realizada ou proposta** — Carregar os itens em uma única consulta com junção; sem cache novo e sem alterar autorização.

4. **Resultado comparativo** — p95 840 → 310 ms (mediana de 30 execuções); memória +3%. Latência de cauda p99 também caiu (1,9 s → 0,7 s).

5. **Validação** — Testes funcionais e de isolamento entre tenants passam; consulta ainda filtra por tenant. Dados de benchmark sintéticos.

6. **Próximo passo e segurança** — Sem enfraquecimento de controles. Risco residual: paginação sem teto máximo (sugerido limitar a 100 itens). Medir em produção após o deploy.
