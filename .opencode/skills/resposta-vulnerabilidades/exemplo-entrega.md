# Exemplo de entrega — `resposta-vulnerabilidades`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Achado e estado** — Alerta do scanner: `libexemplo` 2.3.1, CVE de injeção de comando. Aplicável: sim (versão no lockfile e na imagem implantada).

2. **Risco contextual** — Alcançável por entrada do usuário em `/exportar`; exposto à internet; sem exploração ativa conhecida (consulta ao catálogo de explorações em 22/11/2026). Impacto alto, confiança alta.

3. **Ação** — Atualizar para 2.4.0 (correção compatível) e validar o argumento recebido com lista de valores permitidos. Patch mínimo em 2 arquivos; sem outras atualizações misturadas.

4. **Evidência de correção** — Teste novo falha na 2.3.1 e passa na 2.4.0; regressão verde; SBOM da imagem final mostra 2.4.0. Reexecução do scanner limpa (evidência complementar).

5. **Implantação e rollback** — Deploy canário em 10%, depois 100%; rollback para a imagem anterior se erro > 1%. **Estados distintos:** código corrigido ✔, artefato construído ✔, risco eliminado em produção — só após o deploy.

6. **Pendências** — Confirmar a versão em produção após o deploy; ambiente de homologação ainda na 2.3.1 (dono: plataforma, prazo: sexta).
