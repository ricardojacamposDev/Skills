# Exemplo de entrega — `seguranca-apis`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e inventário** — API REST de pedidos (v1 e v2) com 24 rotas e 1 webhook de pagamento; contrato OpenAPI revisado contra o código. Encontrada a rota `/v1/export`, ausente do contrato e ainda ativa. Fora do escopo: painel administrativo.

2. **Achados priorizados** — 1) **Vulnerabilidade (alta, confiança alta):** `GET /v2/pedidos/{id}` busca só por id, sem conferir o tenant — leitura de pedidos de outro tenant (BOLA). 2) **Vulnerabilidade (alta, confiança média):** `PATCH /v2/usuarios/{id}` liga o corpo direto ao modelo, aceitando `role` (atribuição em massa). 3) **Fragilidade (média):** webhook de pagamento sem verificação de assinatura nem proteção contra repetição. 4) **Hardening (baixa):** sem limite de taxa em `/v2/login`.

3. **Correções** — Filtro por tenant do contexto autenticado em todas as rotas de pedido (variante em `/v2/pedidos/{id}/recibo` incluída); lista fechada de campos no `PATCH`; verificação HMAC em tempo constante, timestamp máximo de 5 min e idempotência por id do evento; limite de 10 tentativas/min por conta e origem no login; `/v1/export` desativada.

4. **Testes** — Negativos: tenant B lendo pedido do A (404), usuário comum enviando `role` (campo ignorado), webhook com assinatura inválida (401) e repetido (200 sem reprocessar), 11ª tentativa de login (429). Positivo: dono lê o próprio pedido. Todos passam, com dados sintéticos e sem testes ativos em produção.

5. **Riscos residuais** — Exports assíncronos e o painel administrativo não foram examinados; consultas de busca sem teto de custo ainda dependem de decisão de produto.
