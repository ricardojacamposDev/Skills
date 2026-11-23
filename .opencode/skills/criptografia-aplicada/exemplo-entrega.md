# Exemplo de entrega — `criptografia-aplicada`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Escopo e necessidades** — Módulo que protege CPF e telefone no banco e assina links de download. Propriedades: confidencialidade e integridade dos campos; autenticidade dos links. Atacante considerado: acesso de leitura ao banco ou a um backup. Requisito legal específico: não confirmado (perguntar ao responsável).

2. **Achados priorizados** — 1) **Vulnerabilidade (alta, confiança alta):** `cripto.py:18` usa AES em modo ECB com chave fixa no código (padrões repetidos visíveis e chave exposta). 2) **Fragilidade (alta):** `links.py:9` assina com MD5 sem segredo; a assinatura pode ser forjada. 3) **Fragilidade (média):** `cliente.py:31` chama a API de parceiro com `verify=False`. 4) **Hardening (baixa):** nenhum identificador de versão de chave nos dados cifrados. Valores de chave não são reproduzidos aqui.

3. **Decisões e correções** — AEAD (AES-GCM) pela biblioteca de alto nível da plataforma, com nonce de 96 bits aleatório e contexto (id do registro) como AAD; chave de dados em envelope, protegida por chave mestra no KMS, com identificador de versão gravado ao lado do texto cifrado; links assinados com HMAC-SHA-256 e expiração; verificação de certificado ligada. A chave antiga exposta deve ser rotacionada pelo fluxo de `gestao-segredos` (aguardando confirmação do responsável).

4. **Verificação** — Testes com vetores conhecidos; texto cifrado adulterado e AAD trocado são rejeitados; chave errada falha; 100 mil cifragens sem nonce repetido; rotação mantém leitura dos dados antigos. Chaves e dados sintéticos; nenhuma chave real em testes.

5. **Riscos residuais** — Dados já cifrados com ECB precisam de migração (plano em 2 etapas, ainda não executado); o uso pós-quântico não foi avaliado; revisão especializada recomendada para o esquema de rotação.
