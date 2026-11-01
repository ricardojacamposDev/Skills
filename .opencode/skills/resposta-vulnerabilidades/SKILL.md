---
name: resposta-vulnerabilidades
description: Prioriza, contém, corrige e valida vulnerabilidades e exposições de dependências, código, imagens e configuração. Use sempre que o usuário mencionar remediação de CVE, alerta de scanner, Dependabot/Renovate, patch de segurança, falsos positivos, plano de mitigação ou resposta a um finding de segurança.
---

# Resposta a vulnerabilidades

Transforme achados em risco reduzido e verificável. Não atualize dependências indiscriminadamente nem feche alertas apenas para limpar um painel: estabeleça aplicabilidade, reduza exposição e comprove a correção.

## Fluxo de resposta

### 1. Normalize o achado

- Consolide alertas duplicados por componente, versão, caminho e causa raiz.
- Identifique artefato afetado: código próprio, dependência direta/transitiva, imagem base, SO ou configuração.
- Preserve identificadores, fonte, evidência e data; descarte segredos acidentalmente incluídos no alerta.
- Se o achado ainda for apenas uma hipótese, valide com `pesquisa-vulnerabilidades` antes de anunciar impacto confirmado.

### 2. Determine aplicabilidade e prioridade

Verifique:

- versão realmente usada e lockfile/SBOM correspondente;
- presença no artefato implantado, não apenas no repositório;
- alcance do código ou função vulnerável, quando essa informação for confiável;
- exposição externa, privilégios, sensibilidade dos dados e controles compensatórios;
- exploração conhecida, como CISA KEV, e inteligência relevante do fornecedor.

Combine severidade técnica com risco do negócio. CVSS isolado não define fila. Declare incertezas e não invente SLA; use a política da organização quando disponível.

### 3. Escolha a menor resposta eficaz

Considere nesta ordem, conforme o risco:

1. correção disponível e compatível;
2. atualização do componente ou imagem para versão suportada;
3. remoção de dependência ou desativação do recurso afetado;
4. mitigação temporária específica e monitorável;
5. aceite de risco formal, com responsável e prazo, apenas quando cabível.

Não use firewall, WAF ou desativação de scanner como substituto automático de patch. Mitigação temporária precisa de critério de remoção e responsável.

Para mudanças de código:

- corrija a causa raiz e variantes do mesmo padrão no escopo afetado;
- mantenha o patch mínimo e compatível com o estilo do projeto;
- evite atualizações em massa que misturem segurança e mudanças funcionais;
- examine breaking changes, proveniência e integridade dos artefatos;
- não imprima, rotacione ou substitua segredos sem o fluxo autorizado apropriado.

### 4. Contenha quando necessário

Se houver exploração ativa ou exposição grave, separe remediação de resposta a incidente. Preserve evidências, envolva os responsáveis e proponha contenção reversível proporcional. Não apague logs nem faça mudanças destrutivas para “limpar” o ambiente.

### 5. Verifique e feche

Faça testes ativos contra a versão vulnerável somente em ambiente isolado e autorizado, com dados sintéticos e critérios de parada; scanners intrusivos seguem a mesma restrição. Sem essas condições, use análise do artefato e testes locais não intrusivos.

- Rode testes de regressão e um teste que falhe na versão vulnerável e passe na corrigida, quando seguro e viável.
- Confirme que o artefato final contém a versão corrigida e que a configuração insegura não permanece em outro ambiente.
- Reexecute o scanner como evidência complementar, não como única prova.
- Registre falsos positivos com justificativa técnica e escopo; nunca use supressão ampla e permanente sem revisão.
- Planeje rollback e monitore erros, latência e comportamento após a implantação.

## Formato de entrega

1. **Achado e estado** — identificador, componente, versão e aplicabilidade.
2. **Risco contextual** — impacto, alcançabilidade, exposição, exploração conhecida e confiança.
3. **Ação** — patch/mitigação, arquivos alterados e motivo.
4. **Evidência de correção** — testes, build/SBOM/scanner e resultado antes/depois.
5. **Implantação e rollback** — ordem, compatibilidade e monitoramento.
6. **Pendências** — riscos residuais, exceções, responsáveis e prazos.

Distinga claramente “código corrigido”, “artefato construído” e “risco eliminado em produção”; são estados diferentes.
