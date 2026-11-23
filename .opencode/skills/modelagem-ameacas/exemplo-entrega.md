# Exemplo de entrega — `modelagem-ameacas`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo, ativos e fronteiras** — Funcionalidade de upload e compartilhamento de documentos por tenant. Ativos: documentos dos clientes, links de compartilhamento, disponibilidade do armazenamento. Atores: usuário do tenant, usuário de outro tenant, visitante com link, administrador. Fora do escopo: cobrança.

2. **Fluxo de dados** — Navegador → API (fronteira internet/servidor) → serviço de arquivos → armazenamento de objetos (fronteira entre tenants no prefixo do caminho) → fila de varredura de malware. Identidade estabelecida na API; autorização decidida no serviço de arquivos. **Desconhecido:** se o armazenamento aceita URLs pré-assinadas sem expiração (pendente de confirmação).

3. **Ameaças priorizadas** — A1 (alta): usuário do tenant A altera o id para ler documento do tenant B — mitigar. A2 (alta): link de compartilhamento previsível ou sem expiração — mitigar. A3 (média): arquivo malicioso enviado e servido a outros usuários — mitigar. A4 (média): envio de arquivos enormes para esgotar o armazenamento — mitigar com cotas. A5 (baixa): repúdio de uma exclusão — aceitar, com trilha de auditoria.

4. **Mitigações e requisitos** — R1: toda leitura confere o tenant do contexto autenticado (teste negativo entre dois tenants). R2: links com 128 bits aleatórios, expiração e revogação. R3: tipo e conteúdo validados, varredura antes de disponibilizar e `Content-Disposition: attachment`. R4: limite de tamanho e cota por tenant. Detecção: alerta para muitas leituras negadas por usuário. Responsável e prazo registrados em cada item.

5. **Premissas e riscos aceitos** — Premissa: o armazenamento isola por prefixo (a verificar). Risco aceito A5 por 6 meses, com revisão ao introduzir assinatura de documentos.
