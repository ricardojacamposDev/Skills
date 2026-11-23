# Exemplo de entrega — `seguranca-dados-persistencia`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e modelo de dados** — Banco Postgres multitenant (coluna `tenant_id`), com esquema `public` exposto por API diretamente ao navegador. Dados sensíveis: e-mail, endereço e valores de faturas. Conexões: API do cliente (papel `anon`/autenticado), serviço de back-end (chave de serviço) e ferramenta de BI. Análise de migrações e esquema; banco em execução não consultado (sem autorização).

2. **Isolamento e acesso** — RLS ativo em 9 das 12 tabelas; `faturas`, `anexos` e `logs_acesso` sem RLS. Política de `pedidos` usa `tenant_id = current_setting('app.tenant')`, definido pelo cliente por parâmetro. A ferramenta de BI usa uma conta com `SELECT` em todo o esquema.

3. **Achados priorizados** — 1) **Vulnerabilidade (alta, confiança alta):** `faturas` sem RLS e exposta na API — qualquer usuário autenticado lê faturas de todos os tenants. 2) **Vulnerabilidade (alta, confiança média):** o tenant da política vem de parâmetro controlado pelo cliente. 3) **Fragilidade (média):** a conta de BI lê tabelas com dados pessoais. 4) **Hardening (baixa):** backups sem teste de restauração registrado.

4. **Correções e migrações** — Migração 1: habilitar RLS e políticas `USING`/`WITH CHECK` em `faturas`, `anexos` e `logs_acesso`. Migração 2: derivar o tenant de uma claim verificada do token. Conta de BI restrita a visões sem dados pessoais. Ordem: staging, depois produção em janela combinada; reversão por migração inversa. Nada aplicado diretamente em produção.

5. **Testes e riscos residuais** — Em staging, com dois tenants sintéticos: leitura, inserção, atualização e exclusão entre tenants negadas após a migração; usuário do próprio tenant continua com acesso. Não verificado: desempenho das políticas em tabelas grandes e a restauração de backup.
