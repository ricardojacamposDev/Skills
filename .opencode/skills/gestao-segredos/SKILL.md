---
name: gestao-segredos
description: Encontra, contém e previne a exposição de segredos — senhas, chaves de API, tokens, certificados e strings de conexão — no código, no histórico git, em imagens de contêiner, logs e pipelines; conduz rotação segura e define armazenamento e prevenção (pre-commit, push protection, cofres). Use ao pedir varredura de segredos, quando uma chave vazou ou foi commitada, ao configurar variáveis de ambiente, cofres ou segredos de CI, ou ao revisar como a aplicação guarda credenciais.
---

# Gestão de segredos

Segredo exposto é credencial comprometida até prova em contrário: remover do código não desfaz o vazamento, porque o valor continua no histórico, em forks, caches, imagens e logs. O objetivo é encontrar, invalidar pelo fluxo correto, impedir a reincidência e nunca ampliar a exposição durante a investigação.

## 1. Regras de manuseio durante todo o trabalho

- Nunca copie o valor de um segredo para resposta, relatório, issue, commit, log, prompt ou ferramenta externa; informe apenas tipo, localização (arquivo/linha/commit) e status.
- Não teste se uma chave “ainda funciona” usando-a contra o provedor sem autorização explícita: verificar validade também é uso da credencial.
- Não rotacione, revogue ou apague segredos por conta própria: proponha e peça confirmação, porque a rotação pode derrubar serviços em produção.
- Relatórios de varredura com localização de segredos são sensíveis: mantenha fora do git e compartilhe só com quem trata o incidente.

## 2. Descubra onde há segredos

Rode a varredura da bateria, que já mascara valores:

`python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py . --categorias SEGREDO --historico-git`

Complemente conforme o escopo:

- **Árvore de trabalho e histórico:** inclua todas as branches; segredo apagado em commit posterior continua recuperável.
- **Arquivos de configuração e de credencial:** `.env*`, chaves `.pem/.key/.p12`, `credentials.json`, `.npmrc`, `.pypirc`, `kubeconfig`, `terraform.tfstate` (guarda segredos em texto claro).
- **Imagens e artefatos:** `ENV`/`ARG` em Dockerfile, camadas da imagem, bundles de frontend (todo segredo enviado ao navegador é público).
- **Pipelines:** variáveis impressas em logs de CI, `set -x`, artefatos publicados, caches.
- **Ferramentas dedicadas**, quando instaladas e autorizadas (ex.: gitleaks, trufflehog em modo sem verificação online): use como evidência complementar.

Trate cada ocorrência como candidata: diferencie valor real, valor sintético de teste, placeholder e chave pública. Registre falso positivo com justificativa em `--permitir`.

## 3. Contenha e rotacione

Para cada segredo real, na ordem:

1. **Avalie o alcance:** o que a credencial acessa, desde quando está exposta, se o repositório/imagem é ou foi público, quem tem cópia.
2. **Emita uma nova credencial** pelo fluxo do provedor e atualize os consumidores (cofre, variáveis de CI, serviços) antes de revogar a antiga, para evitar indisponibilidade.
3. **Revogue a credencial exposta** e confirme a revogação no provedor.
4. **Procure uso indevido** nos logs de acesso do provedor no período de exposição; havendo sinal de abuso, trate como incidente com `resposta-incidentes`.
5. **Limpe o histórico apenas se necessário e combinado** (ex.: git filter-repo): é reescrita destrutiva que exige coordenação com todos os clones e não substitui a rotação.

Segredo exposto em repositório público: considere-o coletado por robôs em minutos; rotação é imediata, não planejada.

## 4. Armazene corretamente

- Segredos fora do código e da imagem: cofre (Vault, AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Doppler etc.) ou variáveis injetadas em tempo de execução pela plataforma.
- `.env` apenas local, listado no `.gitignore`; versione um `.env.example` com placeholders.
- Privilégio mínimo e escopo por ambiente: credenciais diferentes para desenvolvimento, staging e produção; nunca reutilize a de produção em teste.
- Prefira credenciais de curta duração e identidade de carga de trabalho (OIDC no CI, roles de nuvem) a chaves estáticas de longo prazo.
- Defina dono, data de criação e política de rotação para cada segredo.
- Não registre segredos em logs nem em mensagens de erro; mascare cabeçalhos `Authorization` e cookies de sessão.

## 5. Previna a reincidência

- Hook de pre-commit com detecção de segredos e proteção de push no provedor git, quando disponível.
- Varredura de segredos no CI a cada push (camada estática com `--categorias SEGREDO`) quebrando o build para achados altos.
- Builds com segredos de build (BuildKit `--secret`) em vez de `ARG`/`ENV`.
- Revisão de PR atenta a arquivos de configuração e a novos endpoints que devolvem configuração.

## 6. Valide

- Rerode a varredura (árvore e histórico) e confirme que só restaram falsos positivos registrados.
- Confirme que a aplicação funciona com a credencial nova e que a antiga é recusada pelo provedor.
- Confirme que nenhum relatório, log ou artefato gerado durante o trabalho contém o valor.

## Formato de entrega

1. **Escopo** — locais varridos (árvore, histórico, imagens, CI) e o que ficou de fora.
2. **Achados** — tipo, localização, estado (real, sintético, falso positivo) e exposição; nunca o valor.
3. **Contenção** — rotação proposta/executada, ordem, consumidores atualizados e confirmação de revogação.
4. **Armazenamento e prevenção** — mudanças em cofre, `.gitignore`, hooks e CI.
5. **Pendências e riscos** — rotações aguardando responsável, limpeza de histórico, sinais de uso indevido.

Para a varredura completa do sistema, use `testes-vulnerabilidades`; havendo indício de abuso, `resposta-incidentes`; para segredos em pipelines e artefatos, `supply-chain-construtor`; para dados pessoais expostos junto com credenciais, `privacidade-dados`; para infraestrutura e nuvem, `seguranca-infraestrutura`.
