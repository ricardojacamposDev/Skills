---
name: supply-chain-construtor
description: Endurece a cadeia de suprimentos de software de forma preventiva — seleção e pinning de dependências, builds reproduzíveis, integridade e proveniência de artefatos, SBOM e política de dependências. Use ao adicionar ou atualizar dependências, configurar pipeline de build, publicar ou consumir artefatos, definir política de SBOM/pinning ou exigir proveniência; para CVE e alerta já disparados, use resposta-vulnerabilidades.
---

# Cadeia de suprimentos de software

Cada dependência, ferramenta de build e artefato publicado é superfície de ataque com acesso ao seu código e pipeline. O objetivo aqui é preventivo: reduzir a chance de entrada e encurtar a detecção quando algo entrar. Para responder a alerta de CVE já existente, o fluxo é `resposta-vulnerabilidades`.

## 1. Conheça o que você consome

- Inventário real a partir do artefato implantado (lockfile, SBOM, imagem base), não da memória: inclua transitivas, ferramentas de build, actions/plugins de CI e scripts de build.
- Registre para cada dependência relevante: origem, mantenedor, licença, versão fixada, caminho de uso e criticidade.
- Verifique a saúde antes de depender: atividade de manutenção, processo de release, históricos de segurança e existência de canal seguro para avisos.
- Distinga dependência essencial de conveniência; cada uma nova é custo permanente de atualização e resposta.

## 2. Adicione e atualize com critério

- Justifique a necessidade e avalie alternativas (inclusive não adicionar) com `arquitetura-aplicacoes-web`.
- Prefira releases versionadas assinadas a tags flutuantes, branches ou commits arbitrários; `latest` em build é risco, não conveniência.
- Fixe versões em lockfile comprometido no repositório; atualização é mudança deliberada com revisão de changelog, breaking changes e testes — não efeito colateral.
- Revise o que a atualização traz: novas transitivas, scripts de instalação, permissões pedidas e mudança de mantenedor/namespace; confusão de namespace e typosquatting são vetores concretos.
- Automação de atualização (Renovate/Dependabot) com revisão humana proporcional ao risco; não aceite em massa sem ver o que mudou.

## 3. Torne os builds confiáveis

- Ambiente de build efêmero e isolado; ferramentas e imagens fixadas por digest, não por tag mutável.
- Privilégio mínimo por etapa: sem rede onde não precisa, sem credenciais onde não usa; segredos só injetados nas etapas que os exigem e nunca em logs ou artefatos.
- Cache verificado: origem e integridade do conteúdo em cache; build reprodutível quando viável para comparar artefatos.
- Scripts de CI (actions/plugins) são dependências também: fixe por commit/versão e revise mudanças.
- Tokens de CI escopados, curtos e auditados; comprometimento de pipeline exige rotação imediata, tratada como incidente com `resposta-incidentes`.

## 4. Garanta integridade e proveniência

- Publique artefatos com checksum assinado; adote assinatura de artefatos/containers (ex.: sigstore/cosign) quando o ecossistema oferecer.
- Gere e registre proveniência do build: qual fonte, qual pipeline, quais ferramentas produziram o artefato; use níveis SLSA como meta progressiva, não como selo instantâneo.
- **Verifique no consumo:** conferir assinatura/checksum ao puxar dependências e imagens, inclusive no runtime quando aplicável; confiança publicada não é confiança verificada.
- Falha de verificação bloqueia o uso com mensagem clara; não contorne com `--insecure` em pipeline.

## 5. Mantenha SBOM e política

- Gere SBOM por build a partir do artefato final (formato consumível: SPDX/CycloneDX), não apenas do repositório; o SBOM descreve o que existe, não o que deveria existir.
- Use o SBOM como insumo de resposta: nova CVE ou advisory consulta o inventário real do artefato implantado, encurtando apuração de aplicabilidade — a execução segue `resposta-vulnerabilidades`.
- Defina política explícita: licenças aceitas, origens permitidas, janela máxima de desatualização e casos de exceção com prazo.
- Registre exceções com justificativa e responsável; política sem exceção registrada será burlada silenciosamente.

## 6. Reaja a eventos da cadeia

- Dependência comprometida ou suspeita: congelar atualizações da origem, verificar presença no inventário por versão/hash, quarentena de artefatos e rebuild a partir de fonte confiável quando aplicável.
- Não reaja com atualização pânica em massa: confirme versões afetadas e caminho de comprometimento antes de agir, conforme `pesquisa-vulnerabilidades`.
- Rode testes de regressão após trocar artefato/versão; confirme no artefato final, não no repositório.
- Documente o evento como incidente e alimente a política com o que permitiria detecção mais rápida.

## Formato de entrega

1. **Inventário** — dependências relevantes, origens, versões fixadas e criticidade.
2. **Controles aplicados** — pinning, isolamento de build, assinatura/verificação, SBOM.
3. **Política** — licenças, origens, janelas de atualização e exceções registradas.
4. **Evidências** — build reproduzível/verificado, SBOM gerado, verificações de integridade.
5. **Pendências e riscos** — lacunas conhecidas e prioridade de fechamento.

Para investigar um achado de segurança na cadeia, use `pesquisa-vulnerabilidades`; para priorizar e corrigir CVE confirmada, `resposta-vulnerabilidades`; para decisões de adicionar/remover dependência, `arquitetura-aplicacoes-web`; para pipelines e deploy, `entrega-producao-observabilidade`.
