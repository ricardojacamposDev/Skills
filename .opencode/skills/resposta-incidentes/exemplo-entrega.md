# Exemplo de entrega — `resposta-incidentes`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Estado** — Severidade 2 (checkout lento para ~30% dos usuários). Escopo **confirmado:** região A. Sem indício de acesso indevido (hipótese descartada até agora).

2. **Linha do tempo** — 14:02 alerta de erro; 14:06 incidente declarado e comandante definido; 14:15 rollback do release 1.8.0; 14:31 latência normalizada; 15:10 encerramento após monitoramento reforçado.

3. **Mitigações aplicadas** — Rollback (reversível) às 14:15. Temporária: limite de concorrência reduzido, dono: plataforma, remover até sexta.

4. **Causas** — **Confirmada:** consulta sem índice no release 1.8.0. **Hipótese em investigação:** o aumento de tráfego agravou o efeito (dono: time de dados).

5. **Ações preventivas** — Teste de carga da consulta antes do release (dono: time de pedidos, prazo: 2 semanas); alerta de p95 por rota (dono: plataforma, 1 semana).

6. **Comunicações** — Status page às 14:10 e a cada 30 min; mensagem final às 15:15. Próximo aviso devido: postmortem em até 5 dias úteis.
