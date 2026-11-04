# Caso dinâmico: autenticação e sessão

**Referências:** CWE-384, CWE-613, CWE-614, CWE-640 · OWASP A07
**Camada:** integração/E2E no framework do projeto · **Pré-requisito:** ambiente controlado e contas sintéticas

## Objetivo

Verificar expiração, revogação, fixação e proteção de cookies/tokens, além do fluxo de recuperação de senha.

## Pré-condições e dados sintéticos

- Conta sintética com senha sintética forte; controle do relógio do teste (clock fake ou sessão com TTL curto configurável).
- Caixa de e-mail sintética ou interceptador local para tokens de recuperação.

## Procedimento

1. **Sessão:** faça login e observe `Set-Cookie` — verifique `Secure` (em HTTPS), `HttpOnly` e `SameSite` explícito.
2. **Fixação:** defina um cookie de sessão antes do login com valor conhecido; após login, o valor deve mudar.
3. **Expiração:** avance o relógio além do TTL e reutilize a sessão — deve ser rejeitada.
4. **Logout/revogação:** após logout, reutilize cookie/token antigo — deve falhar; troca de senha deve revogar outras sessões quando aplicável.
5. **Recuperação de senha:** solicite reset; o token deve ser de uso único, expirar, não aparecer em logs/respostas e a alteração deve revogar sessões ativas; solicitar de novo deve invalidar o anterior.
6. **Token no storage:** verifique se tokens de longo prazo não ficam em `localStorage` quando cookie HttpOnly for viável.

## Resultado esperado (controle presente)

- Flags corretas; rotação de identificador no login; sessão inválida após expiração/revogação; tokens de reset de uso único com TTL curto e sem vazamento.

## Resultado que caracteriza vulnerabilidade

- Sessão antiga aceita após logout/expiração; identificador preservado pós-login; token de reset reutilizável, sem expiração ou exposto em resposta/log; cookie de sessão sem `HttpOnly`/`Secure`.

## Evidência a registrar

- Headers `Set-Cookie` coletados, resultados de reutilização de sessão/token e teste de regressão por item.

## Limites — não faça

- Não teste bloqueio de conta com tentativas em massa nem use contas reais; não reproduza tokens válidos em relatórios.
