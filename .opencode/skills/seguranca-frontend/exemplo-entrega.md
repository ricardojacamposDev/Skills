# Exemplo de entrega — `seguranca-frontend`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e superfície do cliente** — SPA em React com renderização no cliente; comentários de usuários exibidos como HTML; widget de chat e analytics de terceiros. Tokens em `localStorage`. Não executado: testes ativos em staging (sem autorização).

2. **Achados priorizados** — 1) **Vulnerabilidade (alta, confiança média):** `Comentario.tsx:18` usa `dangerouslySetInnerHTML` com texto do usuário sem sanitizar; alcançável por qualquer visitante que poste um comentário. 2) **Fragilidade (alta):** token de acesso de 24 h e refresh token em `localStorage`; um XSS os leva. 3) **Fragilidade (média):** CSP ausente e script do chat sem SRI. 4) **Hardening (baixa):** source maps publicados em produção.

3. **Correções** — Sanitização com biblioteca mantida e configuração restrita no ponto de uso; token de acesso curto em memória e refresh em cookie `HttpOnly; Secure; SameSite=Strict`; CSP com nonce em modo somente-relatório antes de impor; `integrity` no script do chat; source maps removidos do deploy.

4. **Verificação** — Teste com marcador inofensivo em ambiente local: o HTML é neutralizado após a correção; armazenamento do navegador sem tokens após login e logout; CSP efetiva observada no console sem violações do código próprio. Cabeçalhos reais do servidor ainda não conferidos (camada HTTP não autorizada).

5. **Riscos residuais** — Tag manager de marketing carrega scripts de terceiros fora do controle do time; imposição da CSP depende de 2 semanas de relatórios.
