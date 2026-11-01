---
name: arquitetura-aplicacoes-web
description: Analisa e evolui a arquitetura de aplicações web, APIs e serviços, cobrindo requisitos, limites de domínio, contratos, persistência, integrações, decisões e migrações. Use ao iniciar um app/site, planejar uma funcionalidade estrutural, avaliar trade-offs, reduzir acoplamento ou investigar limites arquiteturais.
---

# Arquitetura de aplicações web

Escolha a menor arquitetura que satisfaça requisitos comprovados e permita evolução segura. Não introduza serviços, filas, abstrações ou padrões distribuídos por tendência. Preserve convenções funcionais do projeto e registre trade-offs quando a decisão tiver custo duradouro.

## 1. Entenda o sistema e os requisitos

- Leia a estrutura, dependências, documentação, contratos, testes e fluxo de execução relevantes.
- Identifique usuários, casos de uso, fronteiras de confiança, sistemas externos e restrições operacionais.
- Registre requisitos funcionais e não funcionais: latência, disponibilidade, consistência, volume, privacidade, segurança, custo e prazo.
- Distinga necessidades presentes de hipóteses futuras; não otimize para escala especulativa.

## 2. Modele limites e contratos

- Defina responsabilidades de módulos e dependências permitidas entre eles.
- Mantenha regras de negócio fora de detalhes de transporte e apresentação quando isso reduzir acoplamento real.
- Trate API como contrato: validação, autenticação/autorização, erros, paginação, idempotência e compatibilidade.
- Para integrações externas, defina timeout, tratamento de falha, limites, retries seguros e observabilidade.
- Use eventos e processamento assíncrono somente quando desacoplamento ou latência justificarem consistência eventual e operação adicional.

## 3. Escolha persistência e evolução de dados

- Modele entidades, invariantes, consultas e transações a partir dos casos de uso.
- Defina constraints e índices para garantir corretude e desempenho medido, considerando custo de escrita.
- Documente estratégia de consistência, concorrência, exclusão, retenção e recuperação quando pertinente.
- Planeje migrações compatíveis e reversíveis quando possível; considere versões simultâneas durante deploy.
- Para dados pessoais, minimize campos e finalidade e trate retenção e exclusão com `privacidade-dados`.

## 4. Avalie trade-offs e riscos

Compare apenas alternativas plausíveis usando critérios relevantes, como:

- simplicidade de desenvolvimento e operação;
- mudança e crescimento esperados;
- falhas e limites de dependências;
- segurança, privacidade e isolamento de tenants;
- custo, latência, consistência e reversibilidade.

Use um registro breve de decisão para escolhas difíceis de reverter: contexto, opções, decisão, consequências e sinais que justificariam revisá-la. Não apresente uma preferência como requisito técnico.

## 5. Prove a arquitetura pelo comportamento

- Valide contratos e invariantes com testes adequados, não apenas diagramas.
- Teste migrações e compatibilidade quando houver alteração de dados ou API.
- Faça análise de ameaças para mudanças de fronteira, identidade, autorização, dados sensíveis ou integrações.
- Meça gargalos antes de adicionar cache, particionamento ou paralelismo.
- Revise se a solução segue o estilo do repositório e pode ser operada, observada e implantada com os recursos existentes.

## Formato de entrega

1. **Contexto e requisitos** — observados, assumidos e pendentes.
2. **Limites e contratos** — componentes, dados e integrações afetados.
3. **Alternativas e decisão** — trade-offs e motivos.
4. **Plano de evolução** — compatibilidade, migração, rollout e rollback.
5. **Validação e riscos residuais** — evidências e questões abertas.

Para implementação de UI, complemente com `interface-ux-acessibilidade`; para entrega operacional, use `entrega-producao-observabilidade`. Para ameaças concretas ou controles de segurança, use `seguranca-aplicacoes`.
