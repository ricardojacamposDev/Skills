# Exemplo de entrega — `seguranca-aplicacoes`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e modelo de confiança** — Rota `GET /faturas/<id>` da API multi-tenant. Atores: usuários comuns de tenants diferentes; entrada não confiável: `id`. Analisado: código e testes; não executado: testes ativos.

2. **Achados priorizados** — 1) **Vulnerabilidade (alta, confiança alta):** `faturas.py:12` busca por id sem conferir tenant/dono — leitura de faturas de outro tenant (IDOR/BOLA). 2) **Hardening (baixa):** resposta de erro inclui o caminho do arquivo.

3. **Correções** — Derivar o tenant do contexto autenticado e filtrar a consulta por ele (deny-by-default, 404 se não pertencer); mesmo padrão aplicado a `/faturas/<id>/pdf`, variante do mesmo problema.

4. **Testes** — Positivo: dono lê a própria fatura (200). Negativos: usuário de outro tenant (404), sem autenticação (401), id inexistente (404). Todos passam.

5. **Riscos residuais e limitações** — Exports assíncronos e webhooks não foram examinados; fora do escopo desta entrega.
