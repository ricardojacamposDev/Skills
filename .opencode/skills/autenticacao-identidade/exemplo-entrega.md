# Exemplo de entrega — `autenticacao-identidade`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e modelo de identidade** — SPA + API próprias, login via provedor OIDC externo; tokens guardados no navegador. Analisados: código do cliente, callback e validação na API. Não executado: testes ativos (sem ambiente autorizado).

2. **Fluxos e achados** — 1) **Vulnerabilidade (alta, confiança alta):** `auth/callback.ts:31` aceita qualquer `redirect_uri` que comece com o domínio da empresa (prefixo), permitindo desviar o código de autorização para um subdomínio controlado por terceiros. 2) **Fragilidade (média):** fluxo sem PKCE e sem `state` conferido. 3) **Fragilidade (média):** `api/jwt.ts:12` não restringe os algoritmos aceitos. 4) **Hardening (baixa):** refresh token sem rotação.

3. **Correções** — Correspondência exata de `redirect_uri` em lista fechada; Authorization Code com PKCE e `state` validado; lista fixa de algoritmos (`RS256`) com `iss`/`aud`/`exp` conferidos; rotação do refresh token com detecção de reuso. Variantes do mesmo padrão procuradas no escopo (1 achada em `auth/logout.ts`).

4. **Testes** — Negativos: `redirect_uri` alterado (rejeitado), `state` ausente (rejeitado), token com algoritmo `none` (401), audiência errada (401), refresh reutilizado (sessão revogada). Positivo: login completo. Todos passam; nenhum token ou segredo foi registrado.

5. **Riscos residuais** — SSO SAML do parceiro X não foi examinado; revogação imediata do access token (hoje expira em 10 min) depende de decisão de produto.
