---
name: entrega-producao-observabilidade
description: Prepara e valida a entrega de aplicações web em produção com CI/CD, configuração de ambientes, migrações, deploy gradual, observabilidade, alertas, smoke tests e rollback. Use ao preparar release, corrigir pipeline, planejar implantação, investigar operação ou definir métricas e alertas de produção.
---

# Entrega, produção e observabilidade

Faça mudanças implantáveis, detectáveis e reversíveis. Inspecione primeiro os pipelines, plataforma, ambientes, convenções operacionais e documentação do projeto; não presuma provedor ou arquitetura.

## 1. Avalie prontidão e risco

- Identifique componente, ambiente, dependências, responsáveis e impacto para usuários.
- Verifique build reproduzível, configuração, migrações, compatibilidade entre versões e procedimento de rollback.
- Mapeie limites de recursos, quotas, dependências externas, dados persistentes e segredos necessários.
- Diferencie fatos observados de recomendações; não invente disponibilidade, SLO ou política organizacional.

## 2. Prepare a mudança

- Mantenha configuração específica por ambiente fora do código e valide variáveis obrigatórias na inicialização.
- Nunca exponha segredos em logs, artefatos, imagens, repositório ou saída de CI.
- Torne builds e deploys repetíveis; fixe versões relevantes e preserve proveniência de artefatos.
- Planeje mudanças de schema em etapas compatíveis com versões simultâneas: expandir, migrar, validar e só então remover legado.
- Defina rollout proporcional ao risco — por exemplo, canário ou percentual gradual — sem assumir que toda plataforma os suporta.
- Para mudança arriscada, estabeleça condição objetiva de pausa e rollback antes do deploy.

## 3. Instrumente sem excesso

- Use logs estruturados, métricas e traces conforme a necessidade e ferramentas já adotadas.
- Registre contexto útil, correlação e resultado sem tokens, credenciais, payloads sensíveis ou dados pessoais desnecessários.
- Meça sinais acionáveis: tráfego, erros, latência de cauda, saturação, filas e dependências relevantes.
- Defina alertas com limiar, janela, impacto e ação/rota de atendimento; evite alertas ruidosos sem responsável.
- Considere cardinalidade, custo e retenção ao adicionar labels, eventos ou traces.
- Preserve privacidade por padrão; requisitos de dados pessoais devem ser avaliados com `privacidade-dados`.

## 4. Implante e valide

1. Rode as verificações de CI e testes exigidos pelo projeto.
2. Verifique artefato, configuração e migrações no ambiente-alvo ou equivalente seguro.
3. Execute deploy com autorização e janela apropriadas; não altere produção por conta própria sem pedido e acesso autorizados.
4. Faça smoke tests não destrutivos nos fluxos essenciais e acompanhe erros, latência e saturação.
5. Compare os sinais com a linha de base e critérios de parada; interrompa ou reverta se limites forem excedidos.
6. Confirme estado pós-deploy e comunique claramente o que foi implantado, não apenas o que foi construído.

Não execute testes de carga, falhas ou scanners intrusivos em produção sem escopo e autorização explícitos. Prefira ambientes controlados e dados sintéticos.

## 5. Investigue incidentes com cuidado

- Construa uma linha do tempo usando evidências e preserve logs relevantes conforme política.
- Separe mitigação, causa confirmada e hipótese; evite atribuição prematura.
- Priorize restauração segura, comunicação e proteção de dados.
- Documente impacto, detecção, resposta, recuperação e ações preventivas sem incluir segredos.

## Formato de entrega

1. **Estado de prontidão** — riscos e pré-requisitos.
2. **Plano de release** — artefato, sequência, migrações e rollout.
3. **Observabilidade** — sinais, alertas e critérios de parada.
4. **Validação** — testes, smoke checks e resultado observado.
5. **Rollback e riscos residuais** — procedimento e limitações.

Para dimensionamento, filas ou resiliência sob carga, complemente com `escalabilidade-resiliente`; para correções de vulnerabilidade, use `resposta-vulnerabilidades`.
