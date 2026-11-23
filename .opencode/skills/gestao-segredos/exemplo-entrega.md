# Exemplo de entrega — `gestao-segredos`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo** — Árvore de trabalho e histórico git (todas as branches) varridos com a bateria. Fora do escopo: imagens de contêiner e logs de CI (não acessados).

2. **Achados** — 1) `config/prod.py:14` — token de API de terceiro, **real** (confiança alta); 2) `tests/fixtures/chave.pem` — chave sintética de teste, **falso positivo** registrado; 3) commit `a1b2c3d` — chave removida depois, **continua no histórico**. Nenhum valor é reproduzido aqui.

3. **Contenção** — Proposta (aguardando confirmação do responsável): emitir novo token, atualizar o cofre e o CI, só então revogar o antigo e confirmar a revogação no provedor. Verificar no log do provedor o uso indevido desde a data do commit.

4. **Armazenamento e prevenção** — Mover o segredo para variável injetada pela plataforma; `.env` no `.gitignore` com `.env.example`; hook de pre-commit e varredura de segredos no CI.

5. **Pendências e riscos** — Rotação depende de confirmação. Repositório foi público por 3 dias: tratar como exposto. Limpeza do histórico só se combinada com todos os clones; não substitui a rotação.
