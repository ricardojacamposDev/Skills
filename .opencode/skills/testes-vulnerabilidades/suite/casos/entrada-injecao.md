# Caso dinâmico: entrada, injeção e limites

**Referências:** CWE-89, CWE-78, CWE-22, CWE-20 · OWASP A03
**Camada:** unitário + integração/API · **Pré-requisito:** banco/serviço local descartável

## Objetivo

Provar que entradas externas passam por validação na fronteira e chegam a consultas/comandos/paths por mecanismos seguros, com limites de tamanho e tipo.

## Pré-condições e dados sintéticos

- Banco local com schema de teste e dados sintéticos; payloads de prova inofensivos (marcadores, não destrutivos).

## Procedimento

1. **SQL:** em cada endpoint que filtra/consulta, envie marcadores como `'--`, `" OR 1=1 --`, `'; SELECT 1 --` e um valor contendo caractere especial legítimo (ex.: `O'Brien`). Compare o SQL executado (log de queries do teste) — deve ser parametrizado.
2. **Comando:** em funcionalidades que tratam nomes/arquivos/expressões, envie `;`, `&&`, `|`, crases e espaços; nenhuma execução de processo deve ocorrer com fragmentos do input.
3. **Path:** envie `../`, `..\\`, caminhos absolutos e encodados (`%2e%2e%2f`) em parâmetros de arquivo; o acesso deve permanecer dentro do diretório base.
4. **Limites:** envie campos vazios, excessivamente longos (acima do máximo aceito), tipos incorretos e payloads grandes (por exemplo, 10 MB) — o sistema deve rejeitar/limitar com erro tratado, sem travar ou corromper estado.
5. **Unicode:** envie caracteres de controle, NUL, surrogate inválido e emojis — comportamento deve ser previsível e sem exceções não tratadas.

## Resultado esperado (controle presente)

- Consultas parametrizadas; nenhum processo executado a partir de input; arquivos restritos à base; limites aplicados com erros claros; entradas malformadas não causam 5xx.

## Resultado que caracteriza vulnerabilidade

- Query montada com fragmento do input; erro de banco citando a sintaxe enviada; leitura fora do diretório base; travamento/exceção com payload grande (indicativo de DoS).

## Evidência a registrar

- Payload exato, resposta e log de query (sem dados sensíveis); teste de regressão com o payload representativo.

## Limites — não faça

- Use marcadores inócuos (`SELECT 1`, leitura de caminho de teste criado por você); nunca `DROP`, `UPDATE` em massa, exfiltração ou execução real de comando.
