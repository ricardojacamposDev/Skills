---
name: seguranca-frontend
description: Endurece e revisa a segurança do lado cliente de aplicações web — XSS no DOM, CSP e Trusted Types, armazenamento de tokens e dados no navegador, scripts e iframes de terceiros, postMessage, CORS e CSRF vistos do cliente, clickjacking, segredos em bundles e cabeçalhos de segurança. Use ao revisar ou construir SPA, componentes que renderizam HTML, login no navegador, integração com widgets ou analytics, política CSP, localStorage/sessionStorage ou qualquer código que roda no navegador do usuário, mesmo que o pedido seja apenas funcional.
---

# Segurança do lado cliente

O navegador do usuário é um ambiente que a aplicação não controla: tudo que chega ao cliente é público, e qualquer script que rode na página tem os mesmos poderes que o seu código. A proteção real mora no servidor e no escape correto na saída; o cliente adiciona defesa em profundidade e evita criar riscos novos (guardar token onde um XSS o leva, carregar script de terceiro sem controle).

## 1. Mapeie a superfície do cliente

- Identifique o framework e o modelo de renderização (SSR, CSR, híbrido), as origens de dados (API, URL, `postMessage`, armazenamento) e onde o HTML é montado.
- Liste scripts, estilos, fontes e iframes de terceiros, e os domínios e subdomínios que compartilham cookies.
- Veja onde ficam tokens e dados pessoais (cookies, `localStorage`, `sessionStorage`, memória, IndexedDB) e o que o build embute no bundle.

## 2. Previna XSS no cliente

- Frameworks escapam por padrão: procure os escapes explícitos (`innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `bypassSecurityTrust*`, `document.write`, `insertAdjacentHTML`) e a origem dos dados que chegam a eles.
- Trate URL, hash, `localStorage` e mensagens de outras janelas como entrada não confiável.
- HTML permitido: sanitize com biblioteca mantida e configuração restrita (ex.: DOMPurify), no ponto de uso; não escreva sanitizador próprio.
- Valide esquemas de URL em `href`/`src` (permita `http`, `https`, `mailto`; bloqueie `javascript:` e `data:` onde não couber).
- Evite `eval`, `new Function` e `setTimeout` com texto; use Trusted Types quando o navegador-alvo suportar.
- Saída de modelo de linguagem também é entrada não confiável (`recursos-ia-generativa`).

## 3. CSP e cabeçalhos

- CSP estrita com nonce ou hash e `strict-dynamic`; `object-src 'none'`, `base-uri 'none'` e `frame-ancestors` definido; sem `unsafe-inline`, `unsafe-eval` nem curingas amplos.
- Implante primeiro em modo somente-relatório, colete as violações e só então imponha; mantenha o endpoint de relatório sem dados pessoais.
- Complementos: `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`, `Cache-Control: no-store` em páginas e respostas sensíveis.
- CSP é defesa em profundidade: não substitui o escape correto. Confira o cabeçalho que o servidor realmente envia (a camada HTTP de `testes-vulnerabilidades`, em ambiente autorizado).

## 4. Tokens e dados no navegador

- `localStorage` e `sessionStorage` são legíveis por qualquer script da origem: um XSS vira roubo de sessão. Evite neles tokens de longa duração e dados sensíveis.
- Prefira cookie `HttpOnly; Secure; SameSite` ou um backend intermediário que guarde os tokens (fluxos em `autenticacao-identidade`). Se um access token precisar estar no JavaScript, mantenha-o curto e em memória, sem refresh token no armazenamento.
- No logout, limpe armazenamento, caches e estado da aplicação.
- Todo segredo enviado ao navegador é público: variáveis `NEXT_PUBLIC_`, `VITE_` e similares não são segredos; source maps em produção só sob controle.

## 5. Terceiros e dependências

- Script de terceiro (analytics, tag manager, chat, widget) executa com poderes totais na página: minimize, hospede você mesmo ou use `integrity` (SRI) com `crossorigin`.
- Iframes de terceiros com `sandbox` e permissões mínimas; não exponha dados da página a eles.
- Avalie o que o terceiro coleta (`privacidade-dados`) e as dependências do bundle (`supply-chain-construtor`).

## 6. Mensagens, origens e navegação

- `postMessage`: informe a origem exata no envio (nunca `*` com dado sensível) e, no recebimento, confira `event.origin` e o formato da mensagem.
- Redirecionamento no cliente só para destinos de uma lista permitida; links externos com `rel="noopener noreferrer"`.
- Clickjacking: `frame-ancestors` (ou `X-Frame-Options`) nas páginas sensíveis.
- CORS é política do navegador configurada pelo servidor, não controle de acesso: não use `*` com credenciais nem reflita o `Origin` sem lista permitida.
- Sessões por cookie: `SameSite` mais token anti-CSRF ou verificação de `Origin`; WebSockets verificam a origem no servidor.

## 7. Verifique com evidência

- Rode o app em ambiente de testes, abra as telas alteradas e inspecione a CSP efetiva e as violações no console.
- Confira o armazenamento do navegador após login e logout, e o bundle em busca de segredos e source maps.
- Teste XSS com marcador inofensivo (caso `saida-xss` de `testes-vulnerabilidades`), só com autorização e dados sintéticos; sem elas, limite-se a código e testes locais.
- Ausência de achados não prova ausência de XSS: informe o que não foi coberto. Classifique como vulnerabilidade, fragilidade ou hardening, sem inflar a severidade.
- Não exiba nem reproduza tokens ou segredos encontrados: informe só tipo e localização.

## Formato de entrega

1. **Escopo e superfície do cliente** — telas, componentes, terceiros e onde ficam tokens e dados.
2. **Achados priorizados** — evidência, impacto, severidade e confiança.
3. **Correções** — mudanças feitas ou propostas, pela causa raiz.
4. **Verificação** — testes, cabeçalhos observados e armazenamento conferido.
5. **Riscos residuais** — o que não foi examinado e suposições.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para fluxos de login, OAuth e sessão, use `autenticacao-identidade`; para ameaças e autorização no servidor, `seguranca-aplicacoes`; para validar cabeçalhos e XSS com a bateria, `testes-vulnerabilidades`; para acessibilidade da interface, `interface-ux-acessibilidade`; para testar fluxos no navegador, `testes-e2e`.
