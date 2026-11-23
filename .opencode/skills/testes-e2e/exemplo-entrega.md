# Exemplo de entrega — `testes-e2e`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Risco e escopo** — Jornadas: login, criar pedido, pagar (sandbox) e acesso negado entre tenants. Fora: relatórios e administração (cobertos em camadas menores).

2. **Ambiente** — App e banco locais em contêineres, migrações e seeds determinísticos; contas e dados sintéticos; navegador e framework com versões fixadas; estado limpo ao fim de cada teste.

3. **Estratégia** — Seletores por papel/nome acessível, esperas por condição observável, sessão salva reutilizável, 4 workers; retry só para falha de infraestrutura; screenshot e trace em falha com dados mascarados.

4. **Mudanças** — 4 testes novos em `e2e/checkout.spec.ts` e fixture de conta de teste; sem novas dependências.

5. **Execução** — `npm run e2e -- checkout` → 4 passam em 38 s; suíte completa → 18 passam, 1 falha preexistente em `perfil.spec.ts` (relatada à parte, não relacionada).

6. **Risco residual** — Pagamento com 3D Secure não coberto; estado de indisponibilidade parcial do provedor não simulado.
