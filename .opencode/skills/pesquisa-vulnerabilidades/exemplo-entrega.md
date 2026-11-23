# Exemplo de entrega — `pesquisa-vulnerabilidades`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Resumo** — `libexemplo` 2.3.1 no lockfile; alerta de CVE de injeção de comando. Estado: **hipótese** (código vulnerável presente, alcance ainda não confirmado). Risco contextual: médio.

2. **Escopo e autorização** — Apenas análise passiva (código, lockfile, advisories públicos). Sem teste ativo: não há ambiente isolado autorizado.

3. **Evidências** — `package-lock.json:812` fixa 2.3.1; advisory do fornecedor (consultado em 22/11/2026) indica afetadas < 2.4.0, correção em 2.4.0. A função afetada é `exec()`.

4. **Análise de alcançabilidade** — Nossa única chamada é `utils/export.ts:40`, e o argumento vem de configuração interna, não de entrada do usuário. Pré-condição de ataque (controlar o argumento) não encontrada.

5. **Reprodução segura** — Não realizada (sem ambiente autorizado). Ausência de reprodução significa "não confirmado nas condições testadas", não "seguro".

6. **Conclusão** — Potencial, **não alcançável pelo caminho atual**. Confiança: média (análise estática, sem teste dinâmico).

7. **Recomendações** — Atualizar para 2.4.0 na próxima janela (menor resposta eficaz) e manter o argumento fora do controle do usuário. Corrija via `resposta-vulnerabilidades`.
