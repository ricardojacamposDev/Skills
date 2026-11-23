# Exemplo de entrega — `arquitetura-aplicacoes-web`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Contexto e requisitos** — Loja web com ~2 mil pedidos/dia; precisa enviar e-mail de confirmação. **Observado:** monólito com fila de jobs já em uso. **Assumido:** atraso de até 1 min é aceitável. **Pendente:** o provedor de e-mail tem limite de taxa? (perguntar ao responsável).

2. **Limites e contratos** — Módulo `pedidos` publica o evento `PedidoConfirmado`; módulo `notificacoes` consome e chama o provedor com timeout de 5 s e até 3 tentativas com espera crescente. O consumidor é idempotente pelo id do pedido.

3. **Alternativas e decisão** — (a) chamada síncrona no checkout — descartada: o provedor lento travaria a compra; (b) job na fila existente — **escolhida**, sem novo serviço; (c) broker dedicado — descartada: sem volume que a justifique. Revisar se passar de ~50 mil pedidos/dia.

4. **Plano de evolução** — Compatível com a versão atual (job novo, sem mudança de schema). Rollout por flag, ligada primeiro para 10% dos pedidos; reversão desligando a flag.

5. **Validação e riscos residuais** — Teste de contrato do evento e teste de idempotência (mensagem duplicada = um e-mail). Risco residual: limite do provedor ainda não confirmado.
