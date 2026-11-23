# Exemplo de entrega — `supply-chain-construtor`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Inventário** — Do lockfile e da imagem final: 214 dependências (31 diretas). Críticas: `framework-web`, `lib-pagamento`. Ações de CI usadas: 6, 2 sem versão fixada.

2. **Controles aplicados** — Versões fixadas em lockfile versionado; ações de CI fixadas por commit; imagem base por digest; build em ambiente efêmero; SBOM gerado do artefato final.

3. **Política** — Licenças permitidas: MIT, Apache-2.0, BSD. Origem: só registro oficial. Janela máxima de desatualização: 90 dias. Exceção registrada: `lib-antiga` (responsável e prazo definidos).

4. **Evidências** — Build reproduzido duas vezes com o mesmo digest; assinatura da imagem verificada no deploy; SBOM em formato CycloneDX anexado ao build.

5. **Pendências e riscos** — Assinatura de artefatos npm ainda não adotada; 1 dependência sem mantenedor ativo (plano de substituição em 60 dias).
