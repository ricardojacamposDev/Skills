# Caso dinâmico: upload, arquivos e desserialização

**Referências:** CWE-434, CWE-409, CWE-502 · OWASP A04/A08
**Camada:** integração em ambiente isolado com armazenamento local · **Pré-requisito:** arquivos sintéticos gerados na hora

## Objetivo

Verificar limites de tamanho/tipo, armazenamento seguro, extração segura de arquivos compactados e ausência de desserialização nativa de dados não confiáveis.

## Pré-condições e dados sintéticos

- Imagem válida (PNG pequeno), arquivo com extensão trocada (`png` contendo texto), arquivo grande sintético, ZIP sintético com nome interno `../escape.txt` e um “zip bomb” pequeno (razão alta) apenas se o ambiente suportar com segurança.

## Procedimento

1. Envie a imagem válida e confirme armazenamento com nome gerado pelo servidor, sem preservar o nome do cliente.
2. Envie o arquivo com extensão trocada e com tipo MIME divergente — deve ser rejeitado ou reclassificado com segurança.
3. Envie o arquivo grande e um corpo acima do limite — rejeição limpa, sem consumo descontrolado.
4. Se a aplicação extrai ZIPs: extraia o ZIP sintético e verifique se `../escape.txt` permaneceu dentro do diretório de destino; observe memória/tempo com o arquivo de alta compressão.
5. Identifique pontos que consomem dados serializados (cache, fila, token, sessão, “lembrar-me”). Se usarem formato nativo (pickle, marshal, `unserialize`, `readObject`, BinaryFormatter), confirme a origem confiável; qualquer entrada externa desserializada nativamente é achado.

## Resultado esperado (controle presente)

- Permitlist de tipo/extensão com verificação de conteúdo, limite de tamanho, nome de armazenamento gerado pelo servidor, extração com validação de caminhos e limites, serialização limitada a formatos de dados (JSON + schema).

## Resultado que caracteriza vulnerabilidade

- Arquivo salvo com nome do cliente em caminho executável/servido; tipo aceito só pela extensão; extração escreve fora do diretório ou excede recursos; desserialização nativa de bytes controláveis pelo cliente.

## Evidência a registrar

- Nomes finais dos arquivos, resultados por tentativa, comportamento de extração e teste de regressão para o armazenamento e a extração.

## Limites — não faça

- Não envie payloads executáveis reais, macros ou bombas grandes; o marcador textual e o zip sintético bastam para provar o comportamento.
