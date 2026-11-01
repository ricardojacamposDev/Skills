---
name: seguranca-aplicacoes
description: Aplica threat modeling, secure code review, arquitetura segura e testes de regressão em aplicações, APIs e infraestrutura como código. Use sempre que o usuário pedir revisão de segurança, modelagem de ameaças, autenticação, autorização, criptografia, segredos, OWASP, hardening ou implementação de requisitos de segurança, mesmo que o pedido venha junto de uma nova funcionalidade.
---

# Segurança de aplicações

Construa e revise controles a partir de caminhos de abuso concretos. Um checklist ajuda cobertura, mas não substitui evidência de alcançabilidade, impacto e comportamento do código.

## 1. Entenda o sistema antes de julgar

Identifique:

- ativos e dados sensíveis;
- atores, privilégios e tenants;
- entradas externas e fronteiras de confiança;
- fluxos de autenticação, autorização, dados, segredos e chamadas a terceiros;
- componentes, ambientes e suposições de segurança.

Leia código, configuração, testes e documentação relevantes. Para uma funcionalidade nova, modele ameaças antes de escolher a implementação; para revisão, concentre-se primeiro nas mudanças e nos caminhos por elas afetados.

## 2. Modele ameaças

Use STRIDE ou método adotado pelo projeto sem transformar categorias em achados automáticos. Para cada cenário relevante, descreva:

- ator e capacidade necessária;
- pré-condições e entrada controlada;
- fronteira ou controle contornado;
- impacto técnico e de negócio;
- controle preventivo, detecção e teste.

Considere abuso de lógica, IDOR/BOLA, escalada de privilégio, confusão entre tenants, SSRF, injeção, desserialização, upload, fluxos de recuperação e race conditions quando aplicáveis.

## 3. Revise e implemente controles

### Autenticação e sessão

- Use mecanismos mantidos pelo framework; não invente protocolos.
- Verifique expiração, revogação, rotação, fixação de sessão e proteção de cookies/tokens.
- Não trate token válido como autorização suficiente.

### Autorização e multitenancy

- Aplique deny-by-default e verifique permissão no servidor para cada ação e objeto.
- Derive tenant e identidade de contexto confiável, não de parâmetros arbitrários.
- Teste acesso horizontal e vertical negado, inclusive em endpoints assíncronos e exports.

### Entradas, saídas e comandos

- Valide tipo, formato, tamanho e limites na fronteira de confiança.
- Use consultas parametrizadas e APIs seguras; evite concatenar comandos, SQL e templates.
- Aplique encoding no contexto de saída correto e permitlist para destinos de SSRF quando possível.
- Imponha limites a uploads, parsers, descompressão e payloads.

### Criptografia e segredos

- Use bibliotecas e construções padrão; não crie criptografia própria.
- Gere valores com CSPRNG, proteja chaves fora do código e defina rotação.
- Não registre segredos, tokens ou dados sensíveis. Se encontrar segredo real, não o reproduza no relatório.

### Disponibilidade e dependências

- Configure timeouts, limites de recursos e retries com orçamento e jitter.
- Evite respostas e logs que revelem dados entre tenants.
- Verifique lockfiles, origem de dependências e pipelines de build no escopo da tarefa.

## 4. Classifique achados com evidência

Priorize vulnerabilidades alcançáveis e impacto demonstrável. Para cada finding, registre localização, pré-condições, caminho de abuso, impacto, severidade contextual e confiança. Separe:

- **vulnerabilidade:** caminho concreto de violação;
- **fragilidade:** controle ausente ou fraco que aumenta risco;
- **hardening:** melhoria defensiva sem exploração demonstrada.

Não infle severidade nem apresente uma prática recomendada como incidente confirmado.

## 5. Corrija e teste

Quando solicitado a alterar código, faça o menor patch que remova a causa raiz e procure variantes diretamente relacionadas. Adicione testes positivos e negativos, inclusive autorização entre usuários/tenants. Preserve compatibilidade e evite controles caseiros quando o framework já oferece um mecanismo adequado.

Exija autorização explícita, escopo e critérios de parada para qualquer teste ativo; prefira ambiente isolado e dados sintéticos. Sem confirmação, limite-se à análise estática e a testes locais não intrusivos. Não execute payloads destrutivos, não acesse sistemas fora do escopo e não colete dados reais para demonstrar impacto.

## Formato de entrega

1. **Escopo e modelo de confiança**.
2. **Achados priorizados** — evidência, impacto, severidade e confiança.
3. **Correções** — mudanças feitas ou recomendadas, por causa raiz.
4. **Testes** — casos positivos/negativos e resultados.
5. **Riscos residuais e limitações** — áreas não examinadas e suposições.

Para investigar uma CVE ou reproduzir um achado, use `pesquisa-vulnerabilidades`; para conduzir patch e rollout, use `resposta-vulnerabilidades`. Trate requisitos de dados pessoais também com `privacidade-dados`.
