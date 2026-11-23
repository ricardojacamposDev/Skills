# Exemplo de entrega — `escalabilidade-resiliente`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Carga e SLOs** — **Observado:** 120 req/s no pico, p99 800 ms. **Meta (premissa a confirmar):** suportar 400 req/s com p99 < 1 s e 99,9% de disponibilidade.

2. **Modelo de capacidade** — Cada instância sustenta ~90 req/s antes de saturar o pool de conexões do banco (primeiro recurso limitante). Headroom atual: 35%.

3. **Mudanças propostas ou realizadas** — Aumentar o pool com limite por instância, adicionar limite de concorrência com resposta 429 e trocar o gatilho de autoscaling de CPU para tamanho da fila.

4. **Plano e resultado de testes** — Teste em staging com dados sintéticos: carga esperada, rajada de 3× e queda do banco por 60 s. Resultado: sustenta 380 req/s; recuperação em 40 s. Dependência de pagamento simulada.

5. **Rollout e observabilidade** — Canário em 10% com critério de parada em p99 > 1 s. Painel de saturação do pool e profundidade da fila.

6. **Custo e riscos residuais** — +2 instâncias no pico (custo estimado, a validar). Risco: rajada maior que 3× ainda não testada.
