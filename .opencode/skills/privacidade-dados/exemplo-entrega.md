# Exemplo de entrega — `privacidade-dados`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Mapa de dados e finalidade** — Evento de analytics `checkout_iniciado` envia e-mail e CEP ao fornecedor. Finalidade declarada: medir abandono. **Lacuna:** base legal e contrato de operador não confirmados (perguntar ao DPO).

2. **Riscos de privacidade** — Reidentificação por e-mail + CEP no fornecedor; titulares afetados: todos os compradores. Severidade média, probabilidade média.

3. **Controles** — Remover e-mail do evento e usar identificador pseudonimizado; reduzir CEP para a região; desativar o evento por padrão até haver escolha do titular.

4. **Ciclo de vida** — Retenção de 13 meses no fornecedor (a confirmar); exclusão propaga ao fornecedor por API; backups com expiração definida.

5. **Validação** — Teste com dados sintéticos: filtro de logs remove e-mail; exclusão do titular de teste remove o evento no fornecedor simulado.

6. **Decisões pendentes** — Base legal (consentimento ou legítimo interesse), necessidade de RIPD e cláusulas do contrato: para jurídico/DPO.
