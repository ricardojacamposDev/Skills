# Exemplo de entrega — `seguranca-infraestrutura`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e autorização** — Lido: `infra/*.tf` e `Dockerfile` (arquivos versionados; sem autorização especial). **Não consultado:** conta de nuvem em execução (sem credencial somente leitura autorizada).

2. **Superfície exposta** — Balanceador público na 443; banco em sub-rede privada; papel do CI com acesso à conta inteira.

3. **Achados priorizados** — 1) **Vulnerabilidade (alta):** `sg.tf:8` libera a porta do banco para `0.0.0.0/0`. 2) **Fragilidade (média):** `Dockerfile` roda como root. 3) **Hardening (baixa):** sem versionamento no bucket de logs.

4. **Correções** — Diff de IaC proposto (não aplicado): restringir a regra ao grupo da aplicação; `USER` não root na imagem; plano revisado antes de aplicar, em janela combinada, com rollback.

5. **Riscos residuais** — Drift com o ambiente real não verificado; o bucket de download público foi registrado como exceção justificada (site estático).
