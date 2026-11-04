# Caso dinâmico: autorização entre usuários e tenants (IDOR/BOLA)

**Referências:** CWE-639, CWE-284 · OWASP A01 · Severidade esperada: alta
**Camada:** integração/API, no framework de testes do projeto · **Pré-requisito:** ambiente controlado e contas sintéticas

## Objetivo

Provar que cada ação e objeto exige permissão verificada no servidor, inclusive em endpoints assíncronos, exports e rotas “internas”.

## Pré-condições e dados sintéticos

- Duas contas sintéticas no mesmo tenant: `ana@teste.local` e `beto@teste.local`, senha sintética.
- Uma conta em outro tenant: `carol@outro.local`.
- Objeto próprio de cada conta (ex.: pedido, documento, registro) criado pela própria conta.

## Procedimento

1. Como `ana`, capture os identificadores dos objetos próprios (resposta da criação ou listagem).
2. Como `beto`, tente ler, alterar e excluir cada objeto de `ana` por identificador direto.
3. Repita como `carol` (tenant diferente) contra objetos dos dois tenants.
4. Tente rotas administrativas como usuário comum e rotas comuns como usuário sem autenticação.
5. Repita nos endpoints assíncronos, exports (CSV/JSON), buscas e qualquer rota que aceite `id`, `uuid`, `slug` ou caminho de arquivo.
6. Se a API aceitar `tenant_id`, `org_id` ou similar como parâmetro, envie o tenant de outra conta com o token de `ana`.

## Resultado esperado (controle presente)

- 403/404 (não 200) para todo acesso entre usuários e tenants; mudanças de estado rejeitadas; exports sem dados de outros titulares; parâmetro de tenant ignorado em favor do contexto do token.

## Resultado que caracteriza vulnerabilidade

- Qualquer leitura, escrita, exclusão ou export de objeto alheio; mudança de comportamento por `tenant_id` fornecido pelo cliente; divergência de autorização entre endpoint síncrono e assíncrono/export.

## Evidência a registrar

- Requisição e resposta (headers de autenticação mascarados), status, código do handler responsável e teste de regressão adicionado.

## Limites — não faça

- Não tente enumerar identificadores em massa nem acesse dados de usuários reais; um objeto sintético alheio basta para provar o achado.
