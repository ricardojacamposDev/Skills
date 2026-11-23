# Exemplo de entrega — `codigo-legado-modernizacao`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Mapa e risco** — Rota `/relatorio` gera o PDF mensal, tem 1.100 linhas e nenhum teste; consumida por um cliente externo. Dor: duas falhas em produção neste trimestre. Área congelada por decisão de negócio: cálculo de impostos.

2. **Rede de segurança** — Criados 6 testes de caracterização (golden master do PDF para 3 clientes sintéticos), incluindo um total arredondado que parece bug e foi **fixado como está**. Lacuna: envio por e-mail não é reproduzível em teste (registrado como risco).

3. **Plano incremental** — 1) extrair o cálculo de totais; 2) isolar a geração do PDF; 3) desviar 10% do tráfego para a nova rota por cliente, com reversão por flag. Conclusão: rota antiga sem tráfego por 2 semanas; remoção em etapa própria.

4. **Execução** — Passo 1 feito em um PR (só extração de função); os 6 testes passam sem alteração.

5. **Dados e contratos** — Sem mudança de schema nem de contrato público neste passo. Verificação futura: total mensal por cliente igual entre as duas rotas.

6. **Estado e pendências** — 1 de 3 passos concluído. Próximo: isolar o PDF. Dívida: costura temporária na linha 412, a remover no passo 3.
