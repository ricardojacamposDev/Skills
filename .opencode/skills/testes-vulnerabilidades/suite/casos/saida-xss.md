# Caso dinâmico: saída e XSS por contexto

**Referências:** CWE-79, CWE-80 · OWASP A03
**Camada:** unitário (renderização) + E2E em navegador local · **Pré-requisito:** dados sintéticos

## Objetivo

Provar que conteúdo dinâmico é codificado no contexto de saída correto (HTML, atributo, JavaScript, URL, CSS) e que defesas ativas (CSP) não dependem só de escape.

## Pré-condições e dados sintéticos

- Perfil de teste com campos controláveis: nome, bio, campo de busca e um valor sintético com marcadores: `<probe-xss>'";>&<script>alert(1)</script>` (marca visível e inofensiva).

## Procedimento

1. Grave o valor-marca em cada campo do perfil e renderize a página que o exibe.
2. Inspecione o DOM: o texto deve aparecer como texto, nunca como elemento/atributo executável.
3. Repita no contexto de atributo (`title="..."`, `value="..."`), em URL gerada (`?q=...`), em bloco `<script>`/JSON embutido e em estilo inline.
4. Verifique o comportamento ao clicar/focar elementos construídos com o valor (handlers dinâmicos).
5. Confirme a CSP da página e registre se `unsafe-inline` está presente.
6. Nas visualizações de conteúdo rico (se o produto aceitar HTML), envie vetor mínimo e verifique sanitização (tags permitidas vs. `script`, `iframe`, `onerror`).

## Resultado esperado (controle presente)

- Valor-marca visível como texto em todos os contextos; nada executado; sanitizador remove/executa apenas permitidos; CSP sem `unsafe-inline` para scripts.

## Resultado que caracteriza vulnerabilidade

- Valor-marca interpretado como marcação/atributo/handler em qualquer contexto; `alert`-equivalente executado; sanitização bypass contornável.

## Evidência a registrar

- Screenshot ou dump do DOM com o valor-marca, contexto afetado e teste de regressão por contexto.

## Limites — não faça

- Use apenas marcadores inofensivos e `alert`/marca visual; nada que persista, propague ou afete outros usuários.
