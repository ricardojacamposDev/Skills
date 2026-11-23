---
name: autenticacao-identidade
description: Projeta, revisa e endurece autenticação e identidade — OAuth 2.0/OIDC, SSO/SAML, sessões e cookies, JWT, senhas, MFA e passkeys, recuperação de conta, chaves de API e identidade serviço a serviço. Use ao implementar ou revisar login, logout, tokens, refresh, redirect URI, "lembrar de mim", redefinição de senha, convite, integração com provedor de identidade, API keys ou qualquer fluxo que prove quem é o usuário ou o serviço, mesmo que o pedido seja apenas funcional.
---

# Autenticação e identidade

Autenticar é provar quem chama; decidir o que essa identidade pode fazer é outro controle (autorização). Os erros mais caros nascem de protocolos inventados, validações omitidas (assinatura, audiência, redirect URI) e credenciais que sobrevivem ao logout ou à troca de senha. Use o provedor de identidade ou a biblioteca mantida do ecossistema; não escreva criptografia nem protocolo próprios.

## 1. Delimite o modelo de identidade

- Liste os atores (humanos, serviços, administradores), os clientes (SPA, mobile, página renderizada no servidor, máquina a máquina) e os tenants.
- Identifique quem emite a identidade (provedor próprio ou externo), quais fluxos já existem e onde os tokens vivem (navegador, app, servidor).
- Separe o que é requisito (MFA obrigatório? SSO corporativo?) do que é suposição; não presuma política da organização.
- Leia código, configuração do provedor e testes antes de julgar; para ameaças além da identidade, use `seguranca-aplicacoes`.

## 2. Escolha e valide o fluxo

**OAuth 2.0 / OIDC**
- Authorization Code com PKCE para clientes públicos (SPA, mobile) e, preferencialmente, também para confidenciais; sem implicit e sem password grant.
- `redirect_uri` com correspondência exata e lista fechada; nunca curinga nem prefixo.
- `state` (ou PKCE) contra CSRF no retorno; `nonce` no OIDC, conferido no id_token; validar `iss`, `aud` e `exp` (e o `iss` da resposta de autorização, contra confusão de provedores).
- Escopos mínimos, audiência específica por API, access token de vida curta; refresh token com rotação e detecção de reuso, e revogável.
- SPA: prefira um backend intermediário (BFF) que guarde os tokens no servidor; o navegador só recebe cookie de sessão. Armazenamento no navegador: `seguranca-frontend`.

**JWT**
- Lista fixa de algoritmos aceitos; rejeite `none` e a troca de assimétrico por simétrico.
- Verifique a assinatura antes de confiar em qualquer claim; valide `iss`, `aud`, `exp`, `nbf`.
- Chaves vêm de configuração ou de um JWKS de origem confiável (com cache e limite); nunca aceite chave ou URL fornecida no próprio token (`jwk`, `jku`, `x5u`).
- O payload é legível: sem dado sensível. Token válido não é permissão suficiente.

**SSO / SAML**
- Valide a assinatura da resposta/asserção, o destinatário, a audiência, a validade e o replay, com biblioteca mantida (ataques de reescrita de assinatura XML são reais).

## 3. Sessão e credenciais

- Sessão no servidor ou cookie assinado: novo identificador no login (fixação), expiração ociosa e absoluta, revogação no servidor, logout que invalida de fato.
- Cookies de sessão com `Secure`, `HttpOnly`, `SameSite` explícito e, quando possível, prefixo `__Host-`; com cookies, trate CSRF.
- Senhas: Argon2id (ou scrypt/bcrypt) com parâmetros atuais; comprimento mínimo e checagem contra senhas vazadas sem expor a senha; sem regras de composição arbitrárias; nunca registrar a senha.
- MFA: prefira passkeys/WebAuthn ou app autenticador a SMS; códigos de recuperação de uso único e armazenados com hash.
- Defesa contra abuso: limite por conta e por origem, espera progressiva, sem bloqueio permanente que permita negar acesso à vítima; mensagens e tempos de resposta uniformes para não enumerar usuários.

## 4. Recuperação, convite e troca de credencial

- Tokens de redefinição e convite: gerados com CSPRNG, uso único, curta validade, guardados com hash, invalidados quando a senha muda ou um novo é pedido.
- Redefinir a senha revoga as sessões e os refresh tokens ativos; troca de e-mail confirma também no endereço antigo.
- Links com token não podem vazar por `Referer`, logs ou terceiros; a resposta ao pedido de reset não revela se a conta existe.
- "Lembrar de mim" usa token rotativo e revogável, não uma sessão sem fim.

## 5. Serviço a serviço e chaves de API

- Prefira identidade de carga de trabalho (OIDC, mTLS, papéis de nuvem) a chaves estáticas.
- Chave de API: escopo mínimo, dono, expiração, prefixo identificável, armazenada com hash, rotacionável, nunca na URL. Armazenamento e rotação seguem `gestao-segredos`.

## 6. Autorização depois da identidade

- Autenticado não é autorizado: aplique deny-by-default no servidor, por ação e por objeto, com tenant derivado do contexto confiável. Revise `seguranca-aplicacoes` e o caso `autorizacao-idor` da bateria.

## 7. Prove com testes e evidência

- Casos negativos: token expirado, assinatura inválida, algoritmo trocado, audiência errada, `redirect_uri` alterado, `state` ausente, refresh reutilizado, sessão após logout e após reset, enumeração de usuários, reset reutilizável.
- Testes ativos só com autorização, ambiente controlado e contas sintéticas; use o caso `autenticacao-sessao` de `testes-vulnerabilidades`. Sem autorização, limite-se a código, configuração e testes locais não intrusivos.
- Classifique cada ponto como vulnerabilidade (caminho concreto de abuso), fragilidade ou hardening; não apresente preferência como falha confirmada.
- Não registre, exiba nem reproduza senha, token ou segredo; informe só tipo e localização.

## Formato de entrega

1. **Escopo e modelo de identidade** — atores, clientes, provedor e onde vivem os tokens.
2. **Fluxos e achados** — fluxo analisado, achados com evidência, severidade e confiança.
3. **Correções** — mudanças feitas ou propostas, pela causa raiz.
4. **Testes** — casos positivos e negativos e resultado.
5. **Riscos residuais** — o que não foi examinado e suposições.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para armazenamento de token e XSS no navegador, use `seguranca-frontend`; para ameaças e autorização por objeto, `seguranca-aplicacoes`; para segredos e chaves, `gestao-segredos`; para executar os casos de sessão, `testes-vulnerabilidades`; para dados pessoais envolvidos, `privacidade-dados`; para incidente com credencial vazada, `resposta-incidentes`.
