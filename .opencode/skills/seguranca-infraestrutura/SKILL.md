---
name: seguranca-infraestrutura
description: Revisa e endurece a infraestrutura que executa o sistema — infraestrutura como código (Terraform, CloudFormation), contêineres e Dockerfiles, Kubernetes, configuração de nuvem, rede exposta, identidades e permissões (IAM), TLS e servidores web. Use ao pedir varredura ou revisão de segurança de infraestrutura, cloud, Docker, Kubernetes, firewall/security groups, buckets, permissões de serviço ou exposição de portas, mesmo que venha junto de uma tarefa de deploy.
---

# Segurança de infraestrutura

Grande parte dos incidentes começa na configuração, não no código: bucket público, porta de banco aberta para a internet, contêiner privilegiado, papel de IAM com `*`. Revise a infraestrutura a partir do que está declarado (IaC, manifests, Dockerfiles) e só observe ambientes em execução com autorização. Cada achado precisa de caminho de exposição concreto, não só de desvio de checklist.

## 1. Delimite escopo e autorização

- Liste o que está no escopo: repositórios de IaC, imagens, clusters, contas/projetos de nuvem, domínios.
- **Leitura de arquivos versionados** não exige autorização especial. **Consultar a nuvem ou o cluster em execução** (APIs de configuração, `kubectl get`, scanners de conta) exige permissão explícita, credencial somente leitura e ambiente definido.
- Nunca altere recursos, regras de firewall ou permissões em ambiente compartilhado sem aprovação; proponha a mudança como diff de IaC.
- Nunca faça varredura de portas ou testes de rede contra endereços fora do escopo autorizado.

## 2. Mapeie a superfície exposta

- O que é alcançável da internet: balanceadores, IPs públicos, buckets/CDNs, endpoints de API, painéis administrativos, bancos e filas.
- Fronteiras de confiança: redes/VPCs, sub-redes públicas e privadas, peering, VPN, regras de entrada e saída.
- Identidades: usuários humanos, contas de serviço, papéis assumidos pelo CI e pelas cargas de trabalho, chaves estáticas existentes.
- Dados: onde ficam dados sensíveis, backups e snapshots, e quem pode lê-los.

## 3. Execute a varredura

1. **Bateria do projeto** (IaC, Dockerfile, Kubernetes, CI/CD e segredos):
   `python3 .opencode/skills/testes-vulnerabilidades/suite/varredura.py . --historico-git`
2. **Ferramentas especializadas**, se instaladas e aprovadas (ex.: checkov, trivy config/image, tfsec, kube-bench, hadolint): use como evidência complementar e registre versão e regras aplicadas.
3. **Imagens de contêiner:** pacotes do sistema operacional e bibliotecas da imagem final não aparecem no lockfile; use scanner de imagem ou SBOM do artefato (`supply-chain-construtor`).
4. **Ambiente em execução** (só com autorização): compare o estado real com o IaC para encontrar drift e recursos criados manualmente.

## 4. Revise por domínio

### Rede e exposição
- Bancos, caches, filas e painéis nunca expostos a `0.0.0.0/0`; SSH/RDP só via bastion, VPN ou acesso sob demanda.
- Regras de saída restritas onde há dados sensíveis (reduz exfiltração e SSRF para metadados).
- Metadados de instância protegidos (IMDSv2 ou equivalente).

### Identidade e permissões (IAM)
- Privilégio mínimo: sem `Action: "*"`/`Resource: "*"` fora de casos justificados; papéis separados por serviço e ambiente.
- Sem chaves estáticas de longa duração quando há alternativa (OIDC no CI, identidade de carga de trabalho).
- MFA para humanos, contas raiz sem uso diário, revisão periódica de acessos.

### Armazenamento e dados
- Buckets e snapshots privados por padrão (bloqueio de acesso público), criptografia em repouso, versionamento e logs de acesso para dados críticos.
- Backups testados e protegidos contra exclusão pelo mesmo papel que os cria.
- Estado do Terraform (`tfstate`) em backend remoto criptografado e com acesso restrito: ele contém segredos.

### Contêineres e Kubernetes
- Imagem base mínima fixada por digest, usuário não root, sistema de arquivos somente leitura quando possível, sem segredos em `ENV`/`ARG`.
- Pods sem `privileged`, `hostNetwork`, `hostPath` sensível ou `allowPrivilegeEscalation`; `capabilities: drop: [ALL]`; limites de CPU/memória.
- RBAC mínimo, service accounts sem token montado quando não usam a API, NetworkPolicies isolando namespaces, segredos do cluster criptografados.

### Transporte e servidores web
- TLS 1.2+ com certificados válidos e renovação automática; redirecionamento HTTP→HTTPS e HSTS.
- Cabeçalhos de segurança, páginas de erro genéricas, sem listagem de diretórios nem endpoints de diagnóstico expostos (`/actuator`, `/metrics`, `pprof`, `server-status`). A camada HTTP da bateria verifica esses itens em ambiente autorizado.

### Registro e detecção
- Logs de auditoria da nuvem e do cluster ativos, centralizados e protegidos contra alteração.
- Alertas para mudanças de IAM, abertura de rede, desativação de logs e uso de credenciais raiz (`entrega-producao-observabilidade`).

## 5. Classifique e corrija

- Para cada achado: recurso, configuração, caminho de exposição (quem alcança o quê), impacto e confiança. Separe vulnerabilidade, fragilidade e hardening, como em `seguranca-aplicacoes`.
- Corrija no IaC, não manualmente no console, para não criar drift; uma mudança por vez, com plano (`terraform plan` ou equivalente) revisado.
- Mudanças de rede e IAM podem derrubar serviços: tenha plano de rollback e janela combinada.
- Recurso público intencional (site estático, CDN) é registrado como exceção justificada, não como achado aberto.

## Formato de entrega

1. **Escopo e autorização** — o que foi lido (arquivos) e o que foi consultado em execução.
2. **Superfície exposta** — serviços alcançáveis, fronteiras e identidades relevantes.
3. **Achados priorizados** — recurso, evidência, exposição, severidade e confiança.
4. **Correções** — diffs de IaC/manifests propostos ou aplicados, com plano e rollback.
5. **Riscos residuais** — drift não verificado, contas fora do escopo, exceções aceitas.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para segredos encontrados na infraestrutura, use `gestao-segredos`; para imagens, pipelines e proveniência, `supply-chain-construtor`; para a varredura executável, `testes-vulnerabilidades`; para deploy, alertas e rollback, `entrega-producao-observabilidade`; para limites e capacidade, `escalabilidade-resiliente`.
