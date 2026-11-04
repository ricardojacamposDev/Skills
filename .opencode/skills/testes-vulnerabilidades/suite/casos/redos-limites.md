# Caso dinâmico: negação de serviço por entrada (ReDoS, parsers e limites)

**Referências:** CWE-1333, CWE-400, CWE-407 · OWASP A04
**Camada:** unitário com medidor de tempo + integração com limites · **Pré-requisito:** ambiente local isolado

## Objetivo

Verificar que expressões regulares, parsers e operações custosas têm limites e não degradam catastroficamente com entradas adversariais de tamanho moderado.

## Pré-condições e dados sintéticos

- Padrões de entrada conhecidos do sistema (validadores, filtros de busca, formatação).
- Strings sintéticas adversariais curtas: repetição longa de um caractere (`"a"*100_000`), quase-casamentos para regex (`"a"*30 + "b"` contra padrão `(a+)+`-like), JSON profundamente aninhado, XML/ZIP com alta razão de expansão (apenas pequeno).

## Procedimento

1. **Regex:** para cada padrão aplicado a entrada externa, meça o tempo com a string quase-casamento em escala crescente (1k, 10k, 100k); crescimento superlinear é indicativo de ReDoS.
2. **Aninhamento/parse:** envie JSON/XML YAML sintético com aninhamento profundo (ex.: 10 mil níveis) e observe erro tratado vs. travamento/exceção de pilha.
3. **Operações custosas:** exporte/liste com ordenação sobre campo arbitrário do cliente, filtre com coringa no início (`%termo`) e verifique plano/latência no banco local.
4. **Limites de corpo:** envie requisição acima do máximo documentado — rejeição rápida na borda, sem processar o corpo.
5. Registre p95 do tempo por tamanho, não apenas média pontual.

## Resultado esperado (controle presente)

- Padrões regex sem retrocesso catastrórfico ou com timeout; profundidade de parse limitada; consultas com índices apropriados ou limites de busca; corpo limitado na borda com erro claro.

## Resultado que caracteriza vulnerabilidade

- Tempo superlinear comprovado em padrão aplicável a entrada externa; travamento ou estouro de pilha com payload moderado; ausência de limite de corpo/parse.

## Evidência a registrar

- Tabela tamanho→tempo (p95), padrão regex afetado e teste de regressão com o tamanho limite seguro.

## Limites — não faça

- Meça localmente com tamanes moderados e pare no primeiro travamento; isso caracteriza o achado — não é teste de carga (para carga, `escalabilidade-resiliente` com autorização).
