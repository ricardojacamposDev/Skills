# Exemplo de entrega — `interface-ux-acessibilidade`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Objetivo e fluxo** — Formulário de cadastro em 3 passos para visitantes em celular e teclado. Tarefa principal: criar a conta sem perder dados ao errar.

2. **Mudanças de interface** — Rótulos associados aos campos, resumo de erros no topo com foco movido a ele, valores preservados após erro, estados de carregamento e de falha de rede tratados.

3. **Acessibilidade e responsividade** — Operação completa por teclado, foco visível, ordem de foco previsível; sem informação só por cor; testado em 360 px e 1280 px e com zoom de 200%; respeita `prefers-reduced-motion`.

4. **Evidências** — Fluxo percorrido com mouse e teclado, incluindo erros; verificação automática de nomes acessíveis sem violações. **Não verificado:** leitor de tela real (não afirmar conformidade WCAG completa).

5. **Decisões pendentes** — Mensagem para e-mail já cadastrado: revelar ou não a existência da conta? (decisão de produto/segurança).
