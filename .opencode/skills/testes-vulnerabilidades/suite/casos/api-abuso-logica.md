# Caso dinâmico: abuso de API e lógica de negócio

**Referências:** CWE-307, CWE-770, CWE-915, CWE-213, CWE-840 · OWASP API Top 10 (API3, API4, API6) · OWASP A04 · Severidade esperada: média a alta
**Camada:** integração/API, no framework de testes do projeto · **Pré-requisito:** ambiente controlado, contas sintéticas e limites configuráveis

## Objetivo

Provar que a API limita tentativas e consumo, aceita apenas os campos previstos, devolve só os dados necessários e não permite burlar regras de negócio com valores fora do esperado ou passos fora de ordem.

## Pré-condições e dados sintéticos

- Conta sintética comum (`ana@teste.local`) e conta administrativa sintética (`admin@teste.local`).
- Limites de taxa configurados para valores baixos no ambiente de teste (ex.: 5 tentativas/min), para provar o controle com poucas requisições.
- Fluxo de negócio com regra verificável (ex.: carrinho → pagamento → confirmação; cupom de uso único; saldo).

## Procedimento

1. **Força bruta e limite de taxa:** com a conta sintética, envie senhas erradas até o limite configurado + 1; repita em recuperação de senha, verificação de código (OTP) e endpoints caros (busca, export, upload).
2. **Atribuição em massa:** em criação/edição de perfil ou recurso, envie campos que o cliente não deveria controlar (`role`, `is_admin`, `tenant_id`, `saldo`, `preco`, `owner_id`, `verificado`) e confira o estado persistido.
3. **Exposição excessiva de dados:** compare a resposta de listagens e detalhes com o que a tela usa; procure hash de senha, tokens, dados de outros usuários, campos internos e IDs sequenciais desnecessários.
4. **Valores fora da regra:** quantidade negativa ou zero, preço/desconto enviado pelo cliente, cupom reutilizado, moeda trocada, datas no passado, números muito grandes.
5. **Passos fora de ordem:** chame a confirmação sem o pagamento, repita a etapa final, pule a verificação de e-mail, troque o identificador entre etapas.
6. **Paginação e tamanho:** peça `limit`/`page_size` muito alto e consultas sem filtro; confira teto aplicado pelo servidor.

## Resultado esperado (controle presente)

- 429 (ou bloqueio temporário) ao passar do limite, com `Retry-After`; campos não permitidos ignorados ou rejeitados com 400; respostas apenas com campos do contrato; regras de negócio validadas no servidor; teto de paginação aplicado.

## Resultado que caracteriza vulnerabilidade

- Tentativas ilimitadas de senha/OTP; campo privilegiado aceito e persistido; dado sensível ou de terceiro na resposta; pedido confirmado sem pagamento, cupom reutilizado ou valor negativo aceito; consulta sem teto que degrada o ambiente.

## Evidência a registrar

- Contagem de requisições até o bloqueio, payload com o campo extra e estado persistido antes/depois, campos excedentes da resposta (mascarados), sequência de chamadas do fluxo burlado e teste de regressão por item.

## Limites — não faça

- Não teste limite de taxa contra ambiente compartilhado ou produção, nem com volume que se pareça com negação de serviço; reduza os limites no ambiente de teste em vez de aumentar o tráfego. Não use contas nem meios de pagamento reais.
