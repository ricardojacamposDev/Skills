---
name: seguranca-apis
description: Projeta, revisa e testa a segurança de APIs REST, GraphQL e webhooks — autorização por objeto e por função (BOLA/BFLA), atribuição em massa, exposição excessiva de dados, limites de taxa e de consumo, abuso de fluxos de negócio, APIs esquecidas ou antigas, assinatura e replay de webhooks e chamadas a APIs de terceiros. Use ao criar ou revisar endpoints, contratos OpenAPI/GraphQL, integrações, webhooks, limites e erros de API, ou ao falar em OWASP API Top 10, mesmo que o pedido seja apenas funcional.
---

# Segurança de APIs

Uma API expõe a lógica de negócio diretamente: o atacante escolhe o id, o campo, a ordem das chamadas e a frequência. Os problemas mais caros costumam não ser injeção, e sim autorização que falta num objeto, campo aceito além do previsto e fluxos que podem ser repetidos sem custo. Revise a partir do contrato e do código; um achado precisa de um caminho de abuso concreto.

## 1. Inventarie as APIs e o contrato

- Liste endpoints, métodos, versões, ambientes e consumidores; procure versões antigas, rotas internas ou de depuração expostas e documentação desatualizada (APIs esquecidas).
- Compare o contrato (OpenAPI, esquema GraphQL) com o código: o que a rota realmente aceita e devolve, e quem pode chamá-la.
- Registre para cada rota: identidade exigida, permissão necessária, dados sensíveis devolvidos e se é pública por decisão.

## 2. Autorização por objeto e por função

- **Objeto (BOLA/IDOR):** toda rota que recebe um identificador confere, no servidor, que o objeto pertence ao chamador ou ao tenant dele; vale para leitura, escrita, exclusão, listagens, filtros, exports, recursos aninhados e operações em lote.
- **Função (BFLA):** rotas administrativas e de ações sensíveis exigem o papel correto; não dependa de esconder o endpoint ou do cliente não exibir o botão.
- Derive identidade e tenant do contexto autenticado, nunca de parâmetro, cabeçalho ou corpo; responda 404 ou 403 de forma uniforme para não revelar existência.
- Token válido não é permissão: aplique deny-by-default por ação e por objeto. Fluxos de login e token: `autenticacao-identidade`.

## 3. Entradas e saídas

- **Atribuição em massa:** não ligue o corpo da requisição direto ao modelo; aceite uma lista fechada de campos por operação e ignore ou rejeite os demais (`role`, `is_admin`, `tenant_id`, `preco`).
- **Exposição excessiva:** serialize por um esquema de saída explícito por papel; não devolva o objeto de banco inteiro nem dependa do cliente para filtrar campos.
- Valide tipo, formato, tamanho e limites por esquema; rejeite `Content-Type` inesperado e campos desconhecidos onde o contrato for estrito.
- Paginação com teto máximo, ordenação e filtros restritos a campos permitidos.

## 4. Abuso e consumo de recursos

- Limite de taxa e cotas por identidade, tenant e rota (mais restritivo em login, reset de senha, busca e exportação); resposta 429 com espera, sem bloqueio permanente que permita negar acesso a outra pessoa.
- Limites de tamanho de corpo, tempo de execução, concorrência e custo por requisição.
- **GraphQL:** limite de profundidade e complexidade, número de aliases e de operações em lote, desativação ou controle de introspecção conforme a política, autorização no resolvedor (não só na entrada).
- Fluxos de negócio: identifique operações que não devem se repetir ou ser feitas fora de ordem (cupom, voto, saque, cadastro em massa) e imponha regras e idempotência no servidor.

## 5. Webhooks e integrações

- **Recebendo webhooks:** verifique a assinatura (HMAC com comparação em tempo constante) sobre o corpo bruto, rejeite timestamp antigo e repetição (replay) e processe de forma idempotente; não confie no IP de origem como única prova.
- **Chamando terceiros e URLs informadas pelo usuário:** permitlist de destinos, bloqueio de endereços internos e de metadados de nuvem (SSRF), timeout, limite de tamanho de resposta e tratamento da resposta como entrada não confiável.
- Credenciais de integração: escopo mínimo, armazenadas e rotacionadas conforme `gestao-segredos`.

## 6. Erros, registro e cabeçalhos

- Erros genéricos ao cliente, com identificador de correlação; sem pilha, SQL, caminhos ou versões. Registros sem token, senha nem dados pessoais (`privacidade-dados`).
- Métodos HTTP restritos ao necessário; CORS com lista de origens, nunca refletindo o `Origin` nem `*` com credenciais; `Cache-Control: no-store` em respostas sensíveis.
- Ciclo de vida: versione, avise a depreciação e desative versões antigas de fato.

## 7. Prove com testes e evidência

- Casos negativos: dois tenants tentando ler e alterar objetos um do outro; usuário comum chamando rota administrativa; campos extras no corpo; excesso de requisições; consulta GraphQL profunda; webhook com assinatura inválida e repetido; destino interno informado.
- Testes ativos só com autorização explícita, ambiente controlado e contas e dados sintéticos; use os casos `autorizacao-idor` e `api-abuso-logica` de `testes-vulnerabilidades`. Sem autorização, limite-se a código, contrato e testes locais não intrusivos.
- Classifique cada ponto como vulnerabilidade (caminho concreto de abuso), fragilidade ou hardening, sem inflar a severidade; informe o que não foi coberto.
- Não registre nem reproduza tokens, chaves ou dados pessoais encontrados: informe tipo e localização.

## Formato de entrega

1. **Escopo e inventário** — APIs, versões, consumidores e o que ficou fora.
2. **Achados priorizados** — rota, evidência, caminho de abuso, severidade e confiança.
3. **Correções** — mudanças feitas ou propostas, pela causa raiz e com variantes.
4. **Testes** — casos positivos e negativos e resultado.
5. **Riscos residuais** — o que não foi examinado e suposições.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para identidade, tokens e sessão, use `autenticacao-identidade`; para modelar ameaças antes de construir, `modelagem-ameacas`; para isolamento no banco, `seguranca-dados-persistencia`; para validar com a bateria, `testes-vulnerabilidades`; para limites e capacidade, `escalabilidade-resiliente`; para segredos de integração, `gestao-segredos`.
