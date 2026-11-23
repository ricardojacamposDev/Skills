# Exemplo de entrega — `documentacao-tecnica`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Audiência e objetivo** — Operação de plantão. Pergunta que o documento responde: "o que fazer quando a fila de e-mails passa de 1.000 mensagens?".

2. **Conteúdo** — `docs/runbooks/fila-email-acumulada.md`: sintoma, diagnóstico passo a passo, mitigação, verificação e escalação. Ação destrutiva (limpar a fila) marcada com aviso e pré-condição.

3. **Verificabilidade** — Comandos testados em staging (saída esperada anotada em cada passo). Placeholders no lugar de hosts e credenciais; link para o alerta que dispara o runbook.

4. **Manutenção** — Dono: time de plataforma. Revisar após cada incidente que o usar. Pendente: "validar limite de taxa do provedor com o responsável" (marcado no texto).

5. **Riscos** — O passo 4 depende de uma permissão que o plantão pode não ter; sinalizado no documento.
