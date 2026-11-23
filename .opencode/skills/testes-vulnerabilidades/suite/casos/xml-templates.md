# Caso dinâmico: XML externo (XXE) e injeção de template no servidor (SSTI)

**Referências:** CWE-611, CWE-776, CWE-1336 · OWASP A05, A03 · Severidade esperada: alta
**Camada:** integração em ambiente com rede restrita · **Pré-requisito:** ambiente controlado e arquivos sintéticos

## Objetivo

Provar que parsers de XML não resolvem entidades externas nem expandem entidades sem limite, e que entradas do usuário nunca são avaliadas como template no servidor.

## Pré-condições e dados sintéticos

- Endpoints que aceitam XML direta ou indiretamente (SOAP, SAML, importação, SVG, DOCX/XLSX, RSS).
- Arquivo sintético no servidor de teste, criado pelo próprio teste (ex.: `/tmp/marcador-xxe.txt` contendo `MARCADOR-SINTETICO`).
- Campos que acabam em templates: nome exibido, assunto/corpo de e-mail, mensagens personalizáveis, relatórios.

## Procedimento

1. **XXE de arquivo:** envie XML com `<!DOCTYPE x [<!ENTITY e SYSTEM "file:///tmp/marcador-xxe.txt">]>` e `&e;` num campo refletido; procure `MARCADOR-SINTETICO` na resposta ou no resultado processado.
2. **XXE de rede:** troque o `SYSTEM` por `http://127.0.0.1:PORTA/xxe` de um servidor sintético local e confira se ele recebeu a requisição.
3. **Expansão de entidades:** envie poucas entidades aninhadas (3 níveis × 10 repetições, nunca o “billion laughs” completo) e meça tempo/memória; o parser deve recusar DTD ou limitar a expansão.
4. **Formatos indiretos:** repita 1 e 2 com SVG enviado como imagem e com DOCX/XLSX sintéticos, se o sistema os processa.
5. **SSTI:** em cada campo que vai para template, envie marcadores aritméticos inofensivos em várias sintaxes — `{{7*191}}`, `${7*191}`, `<%= 7*191 %>`, `#{7*191}` — e procure `1337` na saída (página, e-mail, PDF).
6. Se algum marcador for avaliado, pare: registre a evidência e não tente acessar objetos, arquivos ou comandos.

## Resultado esperado (controle presente)

- DTD recusado ou entidades não resolvidas; nenhuma requisição chega ao servidor sintético; expansão limitada sem degradação; marcadores de template aparecem literalmente (`{{7*191}}`), nunca como `1337`.

## Resultado que caracteriza vulnerabilidade

- Conteúdo do arquivo sintético na resposta; servidor sintético recebe requisição; parser consome tempo/memória desproporcional; qualquer marcador aritmético avaliado pelo servidor.

## Evidência a registrar

- Payload sintético usado, trecho da resposta com o marcador, log do servidor sintético, biblioteca/configuração do parser ou template no código e teste de regressão.

## Limites — não faça

- Não leia arquivos reais do sistema (`/etc/passwd`, chaves, configurações), não use metadados de nuvem e não escale um SSTI confirmado para execução de comandos; o marcador aritmético já prova o achado.
