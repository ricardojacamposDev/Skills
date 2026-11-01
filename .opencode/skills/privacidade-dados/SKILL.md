---
name: privacidade-dados
description: Aplica privacidade by design, LGPD/GDPR, mapeamento e minimização de dados, retenção, direitos de titulares, DPIA e proteção contra vazamento em código, logs, analytics e IA. Use sempre que o usuário coletar, armazenar, compartilhar, excluir ou revisar dados pessoais, cookies, telemetria, consentimento ou requisitos de privacidade, mesmo que o foco principal seja funcional ou técnico.
---

# Privacidade e proteção de dados

Reduza exposição desde o desenho: colete menos, limite finalidade e acesso, retenha pelo menor período necessário e torne os fluxos verificáveis. Requisitos jurídicos dependem de contexto; apoie a decisão técnica sem substituir assessoria jurídica ou o encarregado/DPO.

## 1. Mapeie o fluxo antes de propor controles

Para cada dado relevante, registre:

- categoria e se inclui dado pessoal sensível, infantil ou identificador persistente;
- titular, origem, finalidade e necessidade;
- base legal ou outra justificativa indicada pelos responsáveis, sem presumir consentimento;
- controlador, operador, fornecedores e destinatários;
- armazenamento, região, transferências e integrações;
- prazo de retenção, exclusão, anonimização e cópias em backups/logs;
- quem acessa e quais eventos ficam auditados.

Se a finalidade não estiver clara, não normalize coleta adicional “para uso futuro”.

## 2. Aplique privacidade por padrão

- **Minimize:** prefira não coletar; depois agregue, reduza precisão ou use pseudônimo.
- **Separe finalidades:** não reutilize dados ou consentimento de forma incompatível.
- **Restrinja acesso:** menor privilégio, isolamento por tenant e revisões de acesso.
- **Proteja o ciclo de vida:** criptografia apropriada, gestão de chaves, retenção e exclusão verificável.
- **Evite vazamento:** remova dados pessoais de logs, traces, URLs, mensagens de erro, screenshots, fixtures e prompts de modelos.
- **Use dados sintéticos:** anonimização precisa resistir a reidentificação; pseudonimização não equivale a anonimização.
- **Desative por padrão:** telemetria, gravação e compartilhamento não essenciais devem seguir a política aplicável e escolha do titular.

Não use dados pessoais reais em testes locais, demonstrações ou ferramentas externas sem autorização e necessidade explícitas.

## 3. Revise recursos de alto impacto

Dê atenção especial a cookies e SDKs, analytics, geolocalização, biometria, perfilamento, decisões automatizadas, IA generativa, dados infantis, compartilhamento internacional e integrações com terceiros.

Para esses casos, avalie necessidade e proporcionalidade e recomende DPIA/RIPD quando exigida ou prudente. Verifique contratos, configurações de retenção e treinamento de fornecedores, transferências e possibilidade de desativação.

## 4. Implemente direitos e governança técnica

Quando aplicável, projete fluxos para acesso, correção, portabilidade, oposição, revogação e exclusão. Considere identidade verificada, prazo, propagação a sistemas derivados, caches e fornecedores, exceções legais e evidência da operação sem criar novos dados excessivos.

Exclusão deve cobrir índices, réplicas e pipelines derivados conforme a arquitetura. Backups exigem política de expiração e proteção contra restauração silenciosa de dados excluídos.

## 5. Modele riscos às pessoas

Além de confidencialidade, considere reidentificação, inferência, discriminação, vigilância, perda de controle, linkabilidade e exposição involuntária. LINDDUN pode apoiar a análise quando o projeto não tiver método próprio.

Meça controles por comportamento observável, não apenas pela existência de política. Teste filtros de logs, autorização, exportação, retenção e exclusão com dados sintéticos.

## Formato de entrega

1. **Mapa de dados e finalidade** — inclua lacunas e suposições.
2. **Riscos de privacidade** — pessoas afetadas, cenário, severidade e probabilidade qualitativa.
3. **Controles** — mudanças técnicas e organizacionais priorizadas.
4. **Ciclo de vida** — acesso, retenção, direitos, compartilhamento e exclusão.
5. **Validação** — testes executados e evidências.
6. **Decisões pendentes** — base legal, contratos ou interpretações para jurídico/DPO.

Para controles de acesso e vulnerabilidades, complemente com `seguranca-aplicacoes`. Privacidade e segurança se reforçam, mas uma não substitui a outra.
