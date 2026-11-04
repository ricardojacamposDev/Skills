# Caso dinâmico: concorrência, idempotência e condições de corrida

**Referências:** CWE-362, CWE-367, CWE-843 · OWASP A04
**Camada:** integração com banco local · **Pré-requisito:** estado isolado e dados sintéticos

## Objetivo

Verificar que operações concorrentes não corrompem invariantes (saldo, estoque, limite, unicidade) e que chamadas repetidas produzem efeito único quando idempotência for esperada.

## Pré-condições e dados sintéticos

- Recurso com invariantes numéricos (conta sintética com saldo, item com estoque, cupom com limite).
- Cliente de teste capaz de disparar N requisições simultâneas.

## Procedimento

1. **Duplo uso:** dispare 10 requisições simultâneas da mesma operação crítica (resgate de cupom, transferência, checkout) e conte os efeitos aplicados — com a mesma chave de idempotência, o efeito deve ser 1.
2. **Saldo/estoque:** dispare 10 operações de débito concorrentes contra um recurso que comporta apenas 1 — exatamente 1 deve ser aplicada.
3. **TOCTOU:** em fluxos com verificação e uso separados (checar permissão → aplicar), altere o objeto entre as fases usando a mesma sessão; a aplicação deve reverificar.
4. **Registro duplicado:** crie o mesmo registro único (e-mail, username) em paralelo — deve existir 1, com erro tratado para o perdedor.
5. Consulte o estado final no banco diretamente, não só pelas respostas HTTP.

## Resultado esperado (controle presente)

- Efeitos únicos com idempotência; invariantes preservados (saldo/estoque nunca negativos além da regra); unicidade garantida por constraint; erros tratados nas requisições perdedoras.

## Resultado que caracteriza vulnerabilidade

- Múltiplos efeitos da mesma operação; saldo/estoque inconsistentes com as regras; dois registros “únicos”; bypass de verificação entre fases TOCTOU.

## Evidência a registrar

- Estado antes/depois no banco, número de respostas por status e teste de regressão que executa a disputa concorrente.

## Limites — não faça

- Use apenas recursos sintéticos e concorrência moderada (≤10 requisições); não use isso como teste de carga — para carga, use `escalabilidade-resiliente` com autorização.
