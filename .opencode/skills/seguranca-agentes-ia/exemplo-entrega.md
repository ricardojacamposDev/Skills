# Exemplo de entrega — `seguranca-agentes-ia`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e capacidades do agente** — Agente de código local com acesso de leitura e escrita ao repositório, execução de comandos e 2 servidores MCP (issues e banco de dados). Lê issues de contribuidores externos. Aprovação automática ligada para comandos. Credenciais acessíveis: token pessoal do usuário no ambiente.

2. **Riscos e achados** — 1) **Vulnerabilidade (alta, confiança média):** issue externa é lida como contexto e, com aprovação automática e rede aberta, uma instrução escondida nela poderia levar o agente a enviar arquivos para fora (dados privados + conteúdo não confiável + saída de dados). 2) **Fragilidade (alta):** servidor MCP de banco fixado em `latest` e recebendo o token pessoal. 3) **Fragilidade (média):** skill de terceiro com comando que baixa e executa um script remoto. 4) **Hardening (baixa):** sem registro das ferramentas chamadas.

3. **Controles** — Desativar aprovação automática para escrita, rede e execução; credencial dedicada, somente leitura e de curta duração, no lugar do token pessoal; MCP fixado por versão e revisado; skill de terceiro removida até haver revisão do script; execução em contêiner com lista de destinos de rede; confirmação humana para push, instalação de pacotes e envio externo; registro das chamadas.

4. **Verificação** — 3 casos adversariais sintéticos (instrução escondida num arquivo, descrição de ferramenta maliciosa e pedido para enviar um arquivo para fora): o agente não obedeceu aos dois primeiros e pediu confirmação no terceiro. Sem testes ativos em ambientes reais.

5. **Riscos residuais** — Comportamento do servidor MCP após atualizações futuras, injeção por formatos binários não avaliados e a revisão humana dos pedidos de confirmação continuam sendo pontos de falha.
