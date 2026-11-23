# Exemplo de entrega — `entrega-producao-observabilidade`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Estado de prontidão** — Build reproduzível e testes verdes. Migração adiciona uma coluna (compatível com a versão anterior). Risco: dependência externa de pagamento com limite de taxa.

2. **Plano de release** — Artefato `app:1.8.0` (digest registrado) → migração de expansão → rollout canário em 5%, depois 50%, depois 100%, com janela combinada e responsável de plantão.

3. **Observabilidade** — Sinais: taxa de erro, p95, fila de pedidos, falhas de pagamento. Pausar e reverter se erro > 2% por 5 min ou p95 > 1,5 s. Alerta com dono e ação documentada.

4. **Validação** — Smoke tests não destrutivos (login, listar, criar pedido de teste). **Observado** após 5%: erro 0,3%, p95 420 ms (linha de base 400 ms).

5. **Rollback e riscos residuais** — Reverter a flag e o artefato anterior; a coluna nova fica sem uso (compatível). Limitação: reversão de dados escritos na coluna nova não é automática.
