# Exemplo de entrega — `testes-vulnerabilidades`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e autorização** — Camadas: estática (com histórico git) e inventário de dependências. **Não executadas:** consulta ao OSV (sem confirmação do responsável) e HTTP (sem ambiente autorizado informado).

2. **Achados priorizados** — `app/db.py:5` SQL montado com f-string — **hipótese** (alcance não verificado), severidade alta; `config/prod.py:14` possível segredo — **real** após leitura; `.env.example` — **falso positivo** registrado. Evidência de segredo sem o valor.

3. **Evidências** — `relatorio-seguranca/varredura.md` e `.json` (fora do git, citam locais de segredos; compartilhar só com quem trata o caso). Matriz OWASP com itens sem cobertura automática destacados.

4. **Correções e reteste** — Consulta parametrizada em `db.py` + teste que falha na versão antiga e passa na nova; varredura reexecutada: 1 candidato a menos. Rotação do segredo encaminhada a `gestao-segredos`.

5. **Risco residual** — Não coberto: autorização por objeto/tenant, lógica de negócio, fluxos pós-login. Casos dinâmicos recomendados: `autorizacao-idor` e `api-abuso-logica`.
