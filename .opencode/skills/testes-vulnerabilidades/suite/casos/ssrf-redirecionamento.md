# Caso dinâmico: SSRF e redirecionamentos

**Referências:** CWE-918, CWE-601 · OWASP A10
**Camada:** integração em ambiente com rede restrita · **Pré-requisito:** servidor HTTP sintético local e autorização para a bateria de rede

## Objetivo

Provar que destinos de requisição derivados de entrada são filtrados por permitlist e que redirecionamentos abertos não transformam o domínio em intermediário de phishing.

## Pré-condições e dados sintéticos

- Servidor HTTP sintético local (ex.: `http://127.0.0.1:PORTA`) registrando cada requisição recebida.
- Lista de destinos legítimos da funcionalidade (webhooks, imports por URL, avatares).

## Procedimento

1. Aponte a funcionalidade para o servidor sintético local e confirme no log do servidor se o app realmente fez a requisição (e com qual User-Agent/método).
2. Tente destinos bloqueáveis: `http://169.254.169.254/`, `http://localhost:PORTA-ADMIN`, `file:///etc/hostname` (sintético equivalente), `http://[::1]/` e domínio público controlado por você apenas se autorizado.
3. Tente bypasses de sintaxe: `hTTp://`, `http://127.0.0.1@dominio`, `http://dominio@127.0.0.1`, IP em decimal/octal, DNS que resolve localmente (se controlável), e redirects do destino permitido para o servidor sintético.
4. Registre o tempo limite configurado e comportamento com destino lento ou inexistente.
5. **Redirecionamento aberto:** solicite `/sair?url=http://origem-sintetica.invalid` nas rotas de redirect/logout/retorno; a resposta deve recusar ou limitar a origens permitidas.

## Resultado esperado (controle presente)

- Permitlist por host/esquema, resolução validada antes da requisição, redirects do destino revalidados, timeout aplicado; rotas de redirect aceitam apenas destinos previstos.

## Resultado que caracteriza vulnerabilidade

- Servidor sintético recebe requisição para endereço interno/file/metadata; redirect do destino permitido alcança host não permitido; rota de redirect devolve `Location` arbitrário.

## Evidência a registrar

- Log do servidor sintético (linha do request), payload usado e teste de regressão com um dos bypasses.

## Limites — não faça

- Aponte apenas para serviços sintéticos locais; nunca para metadados reais de provedor, hosts de terceiros ou endereços de produção.
