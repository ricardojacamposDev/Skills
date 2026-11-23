---
name: criptografia-aplicada
description: Orienta e revisa o uso correto de criptografia em aplicações — escolha de primitivas e bibliotecas, criptografia autenticada, assinatura, hash e HMAC, geração de aleatórios, gestão e rotação de chaves, erros clássicos (ECB, nonce reutilizado, comparação não constante), TLS e agilidade criptográfica. Use ao proteger dados em repouso ou em trânsito, assinar ou verificar mensagens, escolher algoritmos, gerenciar chaves ou revisar código com AES, RSA, HMAC, hashes ou certificados, mesmo que o pedido seja apenas funcional.
---

# Criptografia aplicada

A criptografia falha quase sempre no uso, não no algoritmo: modo errado, nonce repetido, chave no código, verificação de certificado desligada. A regra central é não inventar: use bibliotecas de alto nível e construções padrão, e gaste o esforço em gerenciar chaves e em escolher o que proteger. Criar protocolo ou primitiva própria é, por si só, um achado.

## 1. Defina o que proteger e de quem

- Para cada dado ou mensagem, declare a propriedade necessária: confidencialidade, integridade, autenticidade, não repúdio.
- Identifique o estado (em repouso, em trânsito, em uso), o atacante considerado (rede, banco, insider, provedor) e requisitos de conformidade; não presuma exigências legais, registre a lacuna.
- Se o dado não precisa existir, não o colete: eliminar é melhor que criptografar (`privacidade-dados`).

## 2. Escolha primitivas e bibliotecas padrão

- Prefira bibliotecas de alto nível mantidas (libsodium, Tink, recursos da plataforma) a montar blocos de baixo nível.
- **Confidencialidade com integridade:** criptografia autenticada (AEAD), como AES-GCM ou ChaCha20-Poly1305. Nunca ECB; CBC e CTR sem autenticação não bastam.
- **Integridade e autenticidade:** HMAC (SHA-256 ou superior) ou assinatura digital (Ed25519, ECDSA P-256, RSA-PSS com chave de 3072 bits ou mais); verifique sempre antes de usar o dado.
- **Hash:** SHA-256/SHA-3 para integridade; MD5 e SHA-1 não servem para segurança. Senhas usam Argon2id, scrypt ou bcrypt (`autenticacao-identidade`), nunca hash rápido.
- **Troca de chaves e derivação:** X25519 ou ECDH, e HKDF para derivar chaves; não reutilize a mesma chave para fins diferentes.
- **Aleatórios:** sempre CSPRNG do sistema (`secrets`, `crypto.randomBytes`, `/dev/urandom`); nunca `random`, `Math.random` ou o relógio para tokens, chaves ou nonces.
- Codificação (Base64, hex) não é criptografia; compressão antes de criptografar pode vazar informação.

## 3. Gerencie chaves

- Gere e guarde chaves em KMS/HSM ou cofre; nunca no código, na imagem, em log ou no repositório (`gestao-segredos`).
- Criptografia em envelope: chave de dados protegida por chave mestra; chaves distintas por finalidade, ambiente e, quando útil, por tenant.
- Identifique a versão da chave em cada dado cifrado para permitir rotação sem perder acesso; defina rotação, revogação, destruição e recuperação.
- Registre e audite o uso das chaves; separe quem opera os dados de quem administra as chaves.

## 4. Evite os erros clássicos

- **Nonce/IV:** único por chave em AES-GCM (contador ou aleatório de 96 bits com limite de volume); repetição destrói a confiabilidade. Considere construções resistentes a erro de nonce quando o contador for difícil de garantir.
- Verifique a autenticação **antes** de decifrar ou interpretar; falha de verificação rejeita sem detalhar o motivo (oráculo de preenchimento).
- Vincule o contexto com dados associados (AAD: id do usuário, tipo de objeto) para impedir troca de textos cifrados entre registros.
- Comparações de segredo e de MAC em tempo constante; evite mensagens de erro e tempos que diferenciem os casos.
- Não confie em dados não autenticados para escolher algoritmo ou chave (ataques de rebaixamento).

## 5. Transporte e certificados

- TLS 1.2 ou superior (1.3 de preferência) com certificados válidos e renovação automática; HSTS em sites.
- Desligar a verificação de certificado (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify`) é um achado, mesmo em "só por enquanto".
- mTLS entre serviços internos quando a identidade do serviço importar; pinning só com plano de rotação.

## 6. Planeje a agilidade criptográfica

- Inclua identificador de algoritmo e versão nos formatos de dados e de protocolo para permitir migração.
- Mantenha um inventário de onde a criptografia é usada e com qual algoritmo, para responder a uma quebra ou deprecação.
- Para dados que precisam permanecer confidenciais por muitos anos, acompanhe os padrões de criptografia pós-quântica (como o ML-KEM) e adote esquemas híbridos quando as bibliotecas estiverem maduras; não implemente por conta própria.

## 7. Verifique

- Busque no código usos de modos, hashes e geradores de aleatórios fracos, chaves fixas e verificação de TLS desativada (a verificação estática de `testes-vulnerabilidades` ajuda, mas não basta).
- Testes: vetores de teste conhecidos, texto cifrado adulterado é rejeitado, chave errada falha, nonces não se repetem, rotação mantém dados antigos legíveis. Use chaves e dados sintéticos; nunca chaves reais em testes.
- Uso fora do padrão ou novo protocolo exige revisão especializada; não aprove por conta própria.
- Não exiba nem reproduza chaves ou segredos encontrados: informe tipo e localização. Classifique como vulnerabilidade, fragilidade ou hardening e informe o que não foi examinado.

## Formato de entrega

1. **Escopo e necessidades** — dados, propriedades, atacante e estado dos dados.
2. **Achados priorizados** — local, evidência, impacto, severidade e confiança.
3. **Decisões e correções** — primitivas escolhidas, gestão de chaves e mudanças propostas.
4. **Verificação** — testes e resultado.
5. **Riscos residuais** — o que não foi examinado e suposições.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para senhas, tokens e sessões, use `autenticacao-identidade`; para cofres e rotação de segredos, `gestao-segredos`; para a camada de dados, `seguranca-dados-persistencia`; para TLS em servidores e infraestrutura, `seguranca-infraestrutura`; para revisar o código em geral, `seguranca-aplicacoes`.
