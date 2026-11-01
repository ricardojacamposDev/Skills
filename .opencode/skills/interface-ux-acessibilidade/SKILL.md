---
name: interface-ux-acessibilidade
description: Projeta, implementa e revisa interfaces web responsivas, usáveis e acessíveis, incluindo fluxos, formulários, navegação por teclado, semântica, estados de interface e design systems. Use ao criar ou melhorar UI/UX, corrigir problemas de acessibilidade, adaptar layouts a dispositivos ou implementar componentes reutilizáveis.
---

# Interface, UX e acessibilidade

Entregue interfaces compreensíveis, consistentes e utilizáveis por pessoas com diferentes dispositivos e capacidades. Preserve a identidade e os padrões existentes do produto; não invente requisitos visuais quando o repositório, design ou pedido já os define.

## 1. Entenda o contexto da experiência

- Identifique público, tarefa principal, contexto de uso, dispositivos e restrições.
- Leia a estrutura, estilos, componentes, tokens e convenções existentes antes de editar.
- Verifique telas e estados relacionados para manter consistência do fluxo, não apenas do componente isolado.
- Separe requisitos explícitos de hipóteses; sinalize decisões que mudem significativamente o fluxo ou o conteúdo.

## 2. Desenhe o fluxo e o conteúdo

- Torne a ação principal e a hierarquia de informação claras.
- Use rótulos específicos, instruções curtas e mensagens de erro que expliquem como corrigir.
- Para formulários, preserve valores após erro, associe rótulos, valide no momento adequado e resuma erros quando útil.
- Defina estados de carregamento, vazio, sucesso, falha, indisponibilidade e conteúdo longo.
- Evite depender apenas de cor, posição, hover ou ícones sem nome para transmitir significado.

## 3. Implemente de forma responsiva e acessível

- Use HTML semântico e controles nativos sempre que atendam à necessidade.
- Garanta operação por teclado, ordem de foco previsível, foco visível e ausência de armadilhas.
- Associe nomes acessíveis, rótulos, instruções e erros aos controles; use ARIA apenas quando semântica nativa não for suficiente.
- Preserve zoom, reflow, contraste e alvos de interação adequados; não imponha dimensões que cortem conteúdo.
- Teste larguras estreitas e amplas, orientação e conteúdo ampliado; evite corrigir apenas um viewport.
- Respeite `prefers-reduced-motion` e evite movimento essencial para compreender ou concluir uma tarefa.
- Mantenha tokens de cor, espaçamento e tipografia e componentes compartilhados quando já existirem.

## 4. Verifique com evidências

1. Rode o app e inspecione as telas alteradas em viewports relevantes, se o ambiente permitir.
2. Complete o fluxo com mouse e teclado, incluindo erros e estados não ideais.
3. Verifique nomes acessíveis, foco, mensagens e semântica com ferramentas disponíveis e inspeção manual.
4. Confira console, layout, conteúdo cortado e regressões nas telas relacionadas.
5. Registre o que não pôde ser verificado; não afirme conformidade WCAG completa com base só em automação.

Não introduza biblioteca de componentes, dependência ou reestruturação global sem necessidade demonstrável. Evite cores e interações específicas de marca sem referência aprovada.

## Formato de entrega

1. **Objetivo e fluxo** — tarefa e usuários considerados.
2. **Mudanças de interface** — telas/componentes e estados tratados.
3. **Acessibilidade e responsividade** — critérios verificados.
4. **Evidências** — testes, viewports e limitações.
5. **Decisões pendentes** — apenas as que exigem direção de produto ou design.

Para validação automatizada de fluxos, use `testes-qualidade-web`; para impacto em métricas de carregamento e interação, complemente com `eficiencia-computacional`.
