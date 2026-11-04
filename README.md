# Skills — Manual de instalação e utilização

Coleção de **16 skills** para agentes [opencode](https://opencode.ai), em português, focadas em desenvolvimento web seguro, privado, testável e operável. Cada skill é um conjunto de instruções versionado em `SKILL.md` que o agente carrega sob demanda; uma delas (`testes-vulnerabilidades`) inclui também uma **bateria executável** de testes de segurança.

## 1. Visão geral

As skills se dividem em duas naturezas:

- **Metodológicas** — orientam como investigar, decidir, implementar e validar: segurança, privacidade, arquitetura, testes, interface, desempenho, escala, entrega, legado, documentação, IA generativa, incidentes e cadeia de suprimentos.
- **Executável** — `testes-vulnerabilidades` traz scripts prontos (scan estático e checagens HTTP) e especificações de casos dinâmicos para implementar na suíte do seu projeto.

| Grupo | Skills |
|---|---|
| Segurança | `seguranca-aplicacoes`, `pesquisa-vulnerabilidades`, `resposta-vulnerabilidades`, `testes-vulnerabilidades` |
| Privacidade e IA | `privacidade-dados`, `recursos-ia-generativa` |
| Qualidade e interface | `testes-qualidade-web`, `interface-ux-acessibilidade` |
| Arquitetura e evolução | `arquitetura-aplicacoes-web`, `codigo-legado-modernizacao`, `documentacao-tecnica` |
| Operação | `entrega-producao-observabilidade`, `escalabilidade-resiliente`, `eficiencia-computacional`, `resposta-incidentes`, `supply-chain-construtor` |

O índice completo, com critérios de escolha e combinações por tipo de trabalho, está em [`.opencode/skills/README.md`](./.opencode/skills/README.md).

## 2. Requisitos

- [opencode](https://opencode.ai/docs/) instalado e funcional.
- Python **3.9+** apenas para a bateria executável (somente biblioteca padrão; nenhuma dependência para instalar).
- Para as checagens HTTP: um ambiente local/staging controlado. Elas **não rodam** contra produção ou terceiros sem autorização explícita.

## 3. Instalação

O opencode descobre skills em dois níveis: **por projeto** (`.opencode/skills/<nome>/SKILL.md`) e **global** (`~/.config/opencode/skills/<nome>/SKILL.md`). Este repositório já segue o layout de projeto.

### 3.1 Por projeto (recomendado)

Clone este repositório e copie as skills para o diretório de configuração do seu projeto:

```bash
git clone <url-deste-repositorio> skills-web
mkdir -p meu-projeto/.opencode/skills
cp -R skills-web/.opencode/skills/. meu-projeto/.opencode/skills/
```

Para instalar apenas um subconjunto (menos ruído para o agente):

```bash
mkdir -p meu-projeto/.opencode/skills
cp -R skills-web/.opencode/skills/seguranca-aplicacoes \
       skills-web/.opencode/skills/testes-vulnerabilidades \
       meu-projeto/.opencode/skills/
```

Instalar por projeto deixa os comandos da bateria executável funcionando com o caminho documentado (`python3 .opencode/skills/testes-vulnerabilidades/suite/...`) e versiona as skills junto com o código que elas orientam.

### 3.2 Global (todos os projetos)

```bash
git clone <url-deste-repositorio> skills-web
mkdir -p ~/.config/opencode/skills
cp -R skills-web/.opencode/skills/. ~/.config/opencode/skills/
```

Atenção: instalada globalmente, a suíte executável fica em `~/.config/opencode/skills/testes-vulnerabilidades/suite/` — ajuste o caminho ao invocar os scripts (o agente localiza a skill, mas o comando documentado assume instalação por projeto). Se usar a bateria com frequência, prefere a instalação por projeto.

### 3.3 Atualização

As skills são texto versionado: para atualizar, `git pull` no clone e repetir a cópia. Não há build nem dependências.

### 3.4 Verificação e solução de problemas

Abra uma **nova sessão** do opencode no projeto (skills são listadas no início da sessão) e peça: “quais skills estão disponíveis?”. Se alguma não aparecer:

1. Confirme que o arquivo se chama exatamente `SKILL.md` (maiúsculas) dentro de `.opencode/skills/<nome>/`.
2. Confirme o frontmatter com `name` e `description` preenchidos.
3. Confirme que `name` é igual ao nome do diretório, em minúsculas, com hífens simples (`^[a-z0-9]+(-[a-z0-9]+)*$`, 1–64 caracteres).
4. Verifique se há permissões bloqueando (seção 7) e nomes duplicados entre local e global.

## 4. Como as skills funcionam

- O agente vê apenas `name` e `description` de cada skill e carrega o conteúdo completo (`SKILL.md`) quando a tarefa é relevante — por isso as descrições são longas e cheias de gatilhos.
- **Uso automático:** descreva a tarefa com objetivo, contexto e resultado esperado; o agente seleciona sozinho.
- **Uso explícito (mais determinístico):** mencione a skill pelo nome no pedido.

Modelo de pedido eficaz:

> Use `[nome-da-skill]` para `[objetivo]` em `[componente/escopo]`. Quero `[análise/plano/implementação]`. Restrições: `[ambiente, autorização, dados de teste]`. Valide com `[testes ou evidências]` e informe limitações e riscos residuais. Não exponha segredos ou dados pessoais.

Exemplo:

> Use `seguranca-aplicacoes` para revisar o fluxo de autorização desta API. Analise o código e os testes, corrija os problemas confirmados e valide que usuários de outros tenants continuam sem acesso.

## 5. Utilização

### 5.1 Escolha e combinação

O guia completo — índice por necessidade, seções “escolha pelo objetivo” e combinações frequentes — está em [`.opencode/skills/README.md`](./.opencode/skills/README.md). Exemplos de sequência:

- **Investigar e corrigir CVE:** `pesquisa-vulnerabilidades` → `resposta-vulnerabilidades` → `testes-qualidade-web` → `entrega-producao-observabilidade`.
- **Validar segurança antes de release:** `testes-vulnerabilidades` (bateria) → triagem com `seguranca-aplicacoes` → correção com `resposta-vulnerabilidades`.
- **Feature com IA generativa:** `arquitetura-aplicacoes-web` → `recursos-ia-generativa` + `privacidade-dados` → `testes-qualidade-web`.

### 5.2 Considerar todas as skills de uma vez

Copie e adapte em qualquer sessão:

> Considere todas as skills deste repositório antes de trabalhar: `arquitetura-aplicacoes-web`, `codigo-legado-modernizacao`, `documentacao-tecnica`, `eficiencia-computacional`, `entrega-producao-observabilidade`, `escalabilidade-resiliente`, `interface-ux-acessibilidade`, `pesquisa-vulnerabilidades`, `privacidade-dados`, `recursos-ia-generativa`, `resposta-incidentes`, `resposta-vulnerabilidades`, `seguranca-aplicacoes`, `supply-chain-construtor`, `testes-qualidade-web` e `testes-vulnerabilidades`. Minha tarefa é: `[descreva o objetivo e o escopo]`. Identifique quais skills se aplicam e use suas orientações em conjunto; explique brevemente qualquer skill não aplicável, sem forçar etapas irrelevantes.

### 5.3 Regras de segurança herdadas

Todas as skills compartilham limites que devem ser respeitados nos pedidos:

- defina escopo (repositório, componente, ambiente);
- testes ativos exigem autorização explícita — sem ela, análise estática e testes locais não intrusivos;
- dados sintéticos em testes; sem segredos ou dados pessoais em logs, relatórios e prompts;
- resultados classificados por evidência (confirmado, hipótese, fragilidade, falso positivo);
- valide com execução antes de declarar sucesso.

## 6. Bateria executável (`testes-vulnerabilidades`)

```bash
# Estático — qualquer repositório, somente leitura, segredos mascarados
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py . --json relatorio.json

# HTTP — apenas ambiente local/staging, exige declaração de autorização
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_http.py \
  --url http://localhost:3000 --autorizado --json http.json
```

- **Estático:** ~45 padrões (segredos, injeção SQL/comando, XSS, SSRF, criptografia fraca, TLS desativado, sessão, traversal, desserialização, ReDoS, logs). Achado = candidato, nunca vulnerabilidade automática.
- **HTTP:** apenas GET/OPTIONS não destrutivos; recusa alvo sem `--autorizado`, recusa host não local sem `--forcar-externo`, interrompe em 5xx.
- **Casos dinâmicos:** 9 especificações em `suite/casos/` (IDOR/tenants, sessão, injeção, XSS, SSRF, upload/desserialização, concorrência, exposição em erros/logs, ReDoS) para implementar no framework de testes do projeto.
- **CI:** código de saída 1 a partir de `--falhar-em alta|media|baixa` (padrão `alta`); falsos positivos revisados via `--permitir`.

Detalhes de uso, allowlist e integração: [`suite/README.md`](./.opencode/skills/testes-vulnerabilidades/suite/README.md).

## 7. Permissões (avançado)

Controle quais skills um agente pode carregar via padrões no `opencode.json` do projeto:

```json
{
  "permission": {
    "skill": {
      "*": "allow",
      "resposta-incidentes": "ask",
      "pesquisa-vulnerabilidades": "ask"
    }
  }
}
```

Valores: `allow` (carrega direto), `ask` (pede aprovação) e `deny` (oculta do agente). Padrões com curinga são suportados, e é possível sobrescrever por agente — veja a [documentação oficial](https://opencode.ai/docs/skills/).

## 8. Criar ou modificar skills

Convenções deste repositório (mantenha-as para consistência):

1. Um diretório por skill em `.opencode/skills/<nome>/SKILL.md`; `name` = nome do diretório, minúsculo com hífens.
2. Frontmatter obrigatório: `name` e `description` (1–1024 caracteres, específica, com gatilhos de uso na terceira pessoa).
3. Corpo: título, parágrafo de princípio, seções numeradas (`## 1. ...`) e fechamento com `## Formato de entrega`.
4. Referências cruzadas apenas para skills existentes; escopo complementar, nunca contraditório com outra skill.
5. Linguagem baseada em evidência: diferencie confirmado/hipótese/fragilidade/falso positivo; exija autorização para teste ativo; dados sintéticos; sem segredos em exemplos.
6. Ao adicionar skill nova: registre no índice e nas combinações de [`.opencode/skills/README.md`](./.opencode/skills/README.md) e atualize o comando da seção 5.2.

## 9. Limitações

- Skills orientam o agente; **não substituem** requisitos do projeto, autorização formal para testes nem revisão humana.
- Ausência de achados da bateria não é prova de segurança — o relatório informa o que não foi coberto.
- As instruções são ponto de partida: adapte à stack, aos contratos e à política da organização.
