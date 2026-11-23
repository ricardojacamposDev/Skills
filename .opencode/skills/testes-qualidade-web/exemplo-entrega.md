# Exemplo de entrega — `testes-qualidade-web`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Risco e escopo** — Fluxo de cadastro e regra de desconto do carrinho (dinheiro e dados pessoais). Premissa: desconto máximo de 30% (confirmada pelo produto).

2. **Estratégia** — Unitário para a regra de desconto (limites 0/30/31%); integração com banco real para persistência; 1 E2E do fluxo completo; verificação de acessibilidade do formulário. Sem mock da integração cujo contrato se valida.

3. **Mudanças** — 9 testes unitários, 3 de integração e 1 E2E; fixtures sintéticas independentes, cada teste prepara e limpa o próprio estado.

4. **Execução** — `npm test` → 13 passam; sem testes ignorados. Falha preexistente em `pdf.test.ts`, relatada separadamente.

5. **Risco residual** — Regressão visual não coberta; concorrência na aplicação do cupom ainda sem teste.
