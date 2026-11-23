---
name: modelagem-ameacas
description: Conduz modelagem de ameaças de um sistema ou mudança antes e durante a construção — escopo e ativos, diagrama de fluxo de dados com fronteiras de confiança, STRIDE e LINDDUN, casos de abuso, priorização, decisão de mitigar/aceitar e conversão das ameaças em requisitos e testes verificáveis. Use ao desenhar uma funcionalidade ou integração nova, mudar fronteiras, identidade, dados sensíveis ou terceiros, preparar uma revisão de arquitetura de segurança ou documentar riscos aceitos, mesmo que o pedido seja apenas funcional.
---

# Modelagem de ameaças

A modelagem responde quatro perguntas: o que estamos construindo, o que pode dar errado, o que faremos a respeito e se isso foi suficiente. Ela é mais barata antes do código e só vale se produzir decisões: requisitos, testes e riscos aceitos com dono. Uma lista genérica de categorias não é um modelo; cada ameaça precisa de ator, caminho e impacto concretos.

## 1. Delimite escopo, ativos e atores

- Defina o que está dentro (uma funcionalidade, um serviço, uma integração) e o que fica de fora; modelos enormes não são concluídos.
- Liste os ativos (dados, contas, disponibilidade, reputação, dinheiro) e o que seria um dano para o negócio e para as pessoas afetadas.
- Liste atores e capacidades: usuário comum, usuário malicioso, outro tenant, administrador, serviço comprometido, insider, terceiro integrado.
- Registre premissas e o que ainda é desconhecido; marque como pendência em vez de presumir.

## 2. Desenhe o fluxo de dados

- Monte um diagrama simples a partir do código, da configuração e da documentação: processos, armazenamentos, entidades externas, fluxos de dados e **fronteiras de confiança** (internet, rede interna, entre tenants, entre serviços, cliente e servidor).
- Marque onde a identidade é estabelecida, onde a autorização é decidida e onde os dados sensíveis cruzam fronteiras.
- Diagrama que não corresponde ao sistema real é pior que nenhum: confira com quem conhece o sistema e com o código.

## 3. Levante as ameaças

- Aplique **STRIDE** a cada elemento e fluxo que cruza fronteira (falsificação, adulteração, repúdio, vazamento de informação, negação de serviço, elevação de privilégio) e **LINDDUN** para riscos de privacidade (`privacidade-dados`), sem transformar categorias em achados automáticos.
- Escreva casos de abuso: "um usuário do tenant A tenta ler faturas do tenant B alterando o id". Cada ameaça traz ator, pré-condição, entrada controlada, fronteira ou controle contornado e impacto.
- Para ativos críticos, use árvore de ataque para ver os caminhos mais baratos para o atacante.
- Considere abuso de lógica, cadeia de suprimentos, terceiros, falhas de operação e engenharia social, e não só falhas de código.

## 4. Priorize e decida

- Classifique por impacto e probabilidade de forma qualitativa, considerando os controles que já existem e o custo do ataque; evite precisão artificial.
- Para cada ameaça, decida: **mitigar**, **evitar** (remover a funcionalidade ou o dado), **transferir** ou **aceitar**. Aceitar exige dono, justificativa e prazo de revisão.
- Prefira controles que eliminam a classe de problema (não coletar o dado, isolar por construção) a controles que dependem de disciplina.

## 5. Converta em requisitos e testes

- Transforme cada mitigação em requisito verificável ("toda rota de fatura confere o tenant do chamador") e em teste, preferindo casos negativos.
- Aponte a skill que detalha o controle: `autenticacao-identidade`, `seguranca-apis`, `seguranca-dados-persistencia`, `seguranca-frontend`, `seguranca-infraestrutura`, `criptografia-aplicada`.
- Inclua detecção: que sinal ou registro mostraria o abuso e quem responde (`entrega-producao-observabilidade`, `resposta-incidentes`).
- Registre o que for decisão difícil de reverter como ADR (`documentacao-tecnica`).

## 6. Mantenha o modelo vivo

- Versione o modelo junto ao código, em texto e diagrama simples, e revise quando mudarem fronteiras, identidade, tipos de dados, terceiros ou exposição.
- Depois de um incidente ou achado, atualize o modelo com o que ele revelou.
- Não use o modelo como prova de segurança: ele orienta decisões e testes; a verificação continua sendo comportamento observado.

## Formato de entrega

1. **Escopo, ativos e fronteiras** — o que está no modelo, ativos e atores.
2. **Fluxo de dados** — diagrama ou descrição com as fronteiras de confiança.
3. **Ameaças priorizadas** — ator, caminho, impacto, probabilidade e decisão.
4. **Mitigações e requisitos** — requisitos verificáveis, testes e dono.
5. **Premissas e riscos aceitos** — o que ficou em aberto, quem aceitou e quando revisar.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para revisar o código e os controles concretos, use `seguranca-aplicacoes`; para a arquitetura e os trade-offs, `arquitetura-aplicacoes-web`; para dados pessoais, `privacidade-dados`; para registrar decisões, `documentacao-tecnica`; para sistemas com agentes de IA, `seguranca-agentes-ia`.
