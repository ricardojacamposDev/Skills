---
name: resposta-incidentes
description: Comanda resposta a incidentes de sistemas e segurança — declaração, severidade, papéis, comunicação, contenção reversível, recuperação, preservação de evidências e postmortem sem culpabilização. Use durante ou após interrupção, vazamento ou suspeita de comprometimento, ao preparar playbook de resposta, definir escalonamento e turnos, ou ao conduzir postmortem.
---

# Resposta a incidentes

Objetivo: restaurar o serviço com segurança e proteger dados, produzindo um registro confiável do que aconteceu. Coordenação supera heroísmo: um incidente mal comunicado causa tanto dano quanto a falha técnica. Quando o gatilho é um finding de segurança específico, a correção em si segue `resposta-vulnerabilidades`; aqui se comanda o evento.

## 1. Detecte e declare

- Defina sinais objetivos de declaração (indisponibilidade, erro acima de limiar, dados incorretos, suspeita de acesso indevido) e quem pode declarar; não exija perfeito diagnóstico para começar.
- Classifique severidade por impacto ao usuário/negócio, não pela causa técnica; melhor declarar e rebaixar depois do que esperar certeza.
- Registre hora de início, detectores que acionaram e escopo inicial conhecido versus presumido.
- Suspeita de vazamento de dados pessoais: envolva desde o início `privacidade-dados`, jurídico/DPO e prazos regulatórios aplicáveis.

## 2. Estabeleça comando e papéis

- Papéis mínimos: **comandante** (decide e prioriza, nem sempre executa), **técnico** (hands on keyboard), **comunicações** (stakeholders/status), **escriba** (linha do tempo).
- Canal dedicado ao incidente, separado da discussão permanente; decisões registradas no canal, com hora.
- Escalonamento com contatos e alternativos definidos antes de precisar; quem está acordado e até quando.
- Um comandante por incidente; transferência de turno registrada com estado atual, ações em andamento e próximos passos.

## 3. Estabilize e contenha

- Priorize restauração segura antes de causa raiz: mitigação reversível primeiro (rollback, desvio de tráfego, desativação de feature, rate limit).
- Ação destrutiva (apagar dados, derrubar instâncias com estado) apenas quando indispensável, registrada com justificativa e quem autorizou.
- Suspeita de comprometimento: preservem-se logs, imagens e artefatos antes de qualquer limpeza; não apague evidências para “normalizar” — contenha isolando, não destruindo. Envolva `resposta-vulnerabilidades` e `pesquisa-vulnerabilidades` para o achado de segurança.
- Credencial suspeita de exposta: rotacione pelo fluxo autorizado; registre local e momento sem reproduzir o valor.
- Interrompa experimentos que piorem o quadro; uma hipótese por vez em ambiente controlado quando possível.

## 4. Comunique com cadência

- Stakeholders definidos por severidade; status page para usuários quando o impacto é visível.
- Atualizações em intervalo fixo e anunciado, mesmo que digam “sem novidade”; factual, sem causa especulativa e sem culpabilização.
- Diferencie na comunicação: observado, hipótese e ação em andamento; não anuncie causa antes de evidência.
- Vazamento de dados: comunicação externa coordenada com jurídico/DPO conforme obrigações legais; não confirme ou negue escopo sem validação.

## 5. Recupere e verifique

- Restaure em etapas com verificação por fluxo essencial (smoke tests) e comparação com linha de base de tráfego, erros e latência, conforme `entrega-producao-observabilidade`.
- Monitoramento intensificado por período definido após restabelecer; atenção a recorrência, efeito da mitigação e novos erros.
- Confirme dados: integridade, duplicação e lacunas para sistemas que recebem reprocessamento/fila acumulada.
- Rebaixe/encerre o incidente com critério explícito, comunicado; estado de mitigação temporária registrado com dono e prazo de remoção.

## 6. Conduza o postmortem

- Sem culpabilização individual: falhas de processo, sistema e informação, não de pessoas; sem isso, os próximos incidentes serão escondidos.
- Estrutura: resumo, linha do tempo (detecção, declaração, ações, resolução), impacto quantificado, causas contributivas em camadas, o que funcionou, o que falhou.
- Distinga causa confirmada de hipótese; investigação pendente vira ação com dono.
- Ações preventivas priorizadas, com responsável e prazo — ação sem dono é intenção, não aprendizado.
- Registre em documento versionado com `documentacao-tecnica` e alimente runbooks e alertas com o que faltou.

## Formato de entrega

1. **Estado** — severidade, escopo confirmado e impacto quantificado.
2. **Linha do tempo** — detecção, declaração, contenção, recuperação, encerramento.
3. **Mitigações aplicadas** — reversíveis/permanentes, com dono e prazo das temporárias.
4. **Causas** — confirmadas vs. hipóteses, com evidência.
5. **Ações preventivas** — priorizadas, com responsável e prazo.
6. **Comunicações** — audiences, momentos e próximos avisos devidos.

Para correção do finding de segurança que originou o evento, use `resposta-vulnerabilidades`; para investigação defensiva do achado, `pesquisa-vulnerabilidades`; para alertas, smoke tests e rollback na recuperação, `entrega-producao-observabilidade`; para obrigações de dados pessoais, `privacidade-dados`.
