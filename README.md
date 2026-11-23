# Skills — Manual de instalação e utilização

Coleção de **19 skills** para agentes [opencode](https://opencode.ai), em português, focadas em desenvolvimento web seguro, privado, testável e operável. Cada skill é um conjunto de instruções versionado em `SKILL.md` que o agente carrega sob demanda; uma delas (`testes-vulnerabilidades`) inclui também uma **bateria executável** de varredura de vulnerabilidades (código, segredos no histórico git, dependências, IaC/CI/CD e HTTP) com relatório consolidado.

## 1. Visão geral

As skills se dividem em duas naturezas:

- **Metodológicas** — orientam como investigar, decidir, implementar e validar: segurança, segredos, infraestrutura, privacidade, arquitetura, testes, interface, desempenho, escala, entrega, legado, documentação, IA generativa, incidentes e cadeia de suprimentos.
- **Executável** — `testes-vulnerabilidades` traz scripts prontos (varredura estática, segredos no histórico, dependências via OSV, checagens HTTP e um orquestrador com relatório único) e especificações de casos dinâmicos para implementar na suíte do seu projeto.

| Grupo | Skills |
|---|---|
| Segurança | `seguranca-aplicacoes`, `pesquisa-vulnerabilidades`, `resposta-vulnerabilidades`, `testes-vulnerabilidades`, `gestao-segredos`, `seguranca-infraestrutura` |
| Privacidade e IA | `privacidade-dados`, `recursos-ia-generativa` |
| Qualidade e interface | `testes-qualidade-web`, `testes-e2e`, `interface-ux-acessibilidade` |
| Arquitetura e evolução | `arquitetura-aplicacoes-web`, `codigo-legado-modernizacao`, `documentacao-tecnica` |
| Operação | `entrega-producao-observabilidade`, `escalabilidade-resiliente`, `eficiencia-computacional`, `resposta-incidentes`, `supply-chain-construtor` |

O índice completo, com critérios de escolha e combinações por tipo de trabalho, está em [`.opencode/skills/README.md`](./.opencode/skills/README.md).

## 2. Requisitos

- [opencode](https://opencode.ai/docs/) instalado e funcional.
- Python **3.9+** apenas para a bateria executável (somente biblioteca padrão; nenhuma dependência para instalar). `git` para procurar segredos no histórico.
- Para as checagens HTTP: um ambiente local/staging controlado. Elas **não rodam** contra produção ou terceiros sem autorização explícita.

## 3. Instalação

O opencode descobre skills em dois níveis: **por projeto** (`.opencode/skills/<nome>/SKILL.md`) e **global** (`~/.config/opencode/skills/<nome>/SKILL.md`). Este repositório já segue o layout de projeto.

### 3.1 Por projeto (recomendado)

Clone este repositório e copie as skills para o diretório de configuração do seu projeto:

```bash
git clone https://github.com/ricardojacamposDev/Skills.git skills-web
mkdir -p meu-projeto/.opencode/skills meu-projeto/.opencode/commands
cp -R skills-web/.opencode/skills/. meu-projeto/.opencode/skills/
cp -R skills-web/.opencode/commands/. meu-projeto/.opencode/commands/
```

A segunda cópia instala os atalhos `/tarefa`, `/revisao-final` e `/varredura-seguranca` (seções 5.2 a 5.4).

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
git clone https://github.com/ricardojacamposDev/Skills.git skills-web
mkdir -p ~/.config/opencode/skills ~/.config/opencode/commands
cp -R skills-web/.opencode/skills/. ~/.config/opencode/skills/
cp -R skills-web/.opencode/commands/. ~/.config/opencode/commands/
```

Atenção: instalada globalmente, a suíte executável fica em `~/.config/opencode/skills/testes-vulnerabilidades/suite/` — ajuste o caminho ao invocar os scripts (o agente localiza a skill, mas o comando documentado assume instalação por projeto). Se usar a bateria com frequência, prefira a instalação por projeto.

### 3.3 Atualização

As skills são texto versionado: para atualizar, `git pull` no clone e repetir a cópia. Não há build nem dependências.

### 3.4 Verificação e solução de problemas

Abra uma **nova sessão** do opencode no projeto (skills são listadas no início da sessão) e peça: “quais skills estão disponíveis?”. Para conferir os atalhos, digite `/` e procure `tarefa`, `revisao-final` e `varredura-seguranca` na lista. Se alguma skill não aparecer:

1. Confirme que o arquivo se chama exatamente `SKILL.md` (maiúsculas) dentro de `.opencode/skills/<nome>/` (ou de `~/.config/opencode/skills/<nome>/`, na instalação global).
2. Confirme o frontmatter com `name` e `description` preenchidos.
3. Confirme que `name` é igual ao nome do diretório, em minúsculas, com hífens simples (`^[a-z0-9]+(-[a-z0-9]+)*$`, 1–64 caracteres).
4. Verifique se há permissões bloqueando (seção 7).

**Skill instalada no projeto e na global ao mesmo tempo.** A skill não some nem aparece duas vezes: o opencode carrega uma só cópia, sem garantia de qual (em teste, parte das skills veio do projeto e parte da instalação global). Enquanto as cópias forem iguais, não há problema. O risco é usar uma versão desatualizada: depois de editar ou atualizar uma skill, repita a cópia para o outro local (seção 3.3). Para ver qual cópia está em uso, rode `opencode debug skill` e confira o campo `location` de cada skill.

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
- **Varredura completa do sistema:** `testes-vulnerabilidades` → `gestao-segredos` / `seguranca-infraestrutura` / `seguranca-aplicacoes` (triagem por tipo) → `resposta-vulnerabilidades`.

### 5.2 Comando único: o agente escolhe as skills

Você não precisa saber quais skills existem nem o que cada termo técnico significa.

**Jeito mais fácil: atalho `/tarefa`.** No opencode, digite `/tarefa` seguido do que você quer, com suas palavras:

```text
/tarefa quero um formulário de contato no site que envie as mensagens para o meu e-mail
```

O atalho fica em `.opencode/commands/tarefa.md`, é instalado junto com as skills (seção 3) e envia ao agente o comando completo. Se você digitar só `/tarefa`, o agente pergunta o que você quer fazer.

**Sem o atalho:**

O texto completo do comando vive em um só lugar, [`tarefa.md`](./.opencode/commands/tarefa.md). Em clientes sem atalhos, abra esse arquivo, copie o texto depois do cabeçalho `---` e troque `$ARGUMENTS` pelo seu pedido (ou apague, se for opcional).

Exemplos de tarefa (valem para o atalho e para o comando):

- “Quero um formulário de contato no site que envie as mensagens para o meu e-mail.”
- “O login está lento; descubra por quê e corrija.”
- “Recebi um alerta de segurança sobre uma biblioteca do projeto; veja se me afeta.”

O comando não lista as skills pelo nome: o agente lê a descrição de cada uma e decide quais usar. Por isso ele continua válido quando novas skills forem adicionadas. Se quiser forçar uma skill específica, use o modelo da seção 4.

**Quando usar:** uma vez por tarefa, no início do pedido. As mensagens seguintes da mesma conversa (“agora mude a cor do botão”) não precisam do atalho, porque o agente continua seguindo as instruções. Perguntas simples (“o que faz este arquivo?”) também não precisam.

### 5.3 Revisão final do projeto: atalho `/revisao-final`

Use no fim de um projeto ou antes de uma entrega, para verificar tudo de uma vez. Ao contrário do `/tarefa`, ele **não altera arquivos**: analisa o projeto inteiro, roda os testes existentes e a varredura de segurança e lista os problemas por prioridade (impede a entrega, importante, pode esperar). Só depois pergunta o que você quer corrigir, e cada correção vem com testes.

```text
/revisao-final
```

Se quiser, acrescente contexto depois do atalho:

```text
/revisao-final é uma loja virtual; vou publicar na semana que vem
```

O atalho fica em `.opencode/commands/revisao-final.md`. **Sem o atalho:**

O texto completo do comando vive em um só lugar, [`revisao-final.md`](./.opencode/commands/revisao-final.md). Em clientes sem atalhos, abra esse arquivo, copie o texto depois do cabeçalho `---` e troque `$ARGUMENTS` pelo seu pedido (ou apague, se for opcional).

Deixar a verificação só para o final encontra os problemas, mas alguns custam mais para corrigir tarde; por exemplo, mudar o jeito de guardar dados pessoais pode exigir refazer parte do código. Um meio-termo: use `/tarefa` nas partes mais sensíveis (login, pagamentos, dados pessoais) e `/revisao-final` antes de entregar.

### 5.4 Varredura de segurança: atalho `/varredura-seguranca`

Procura vulnerabilidades no projeto inteiro sem alterar arquivos: código e configuração, senhas e chaves (inclusive as já apagadas que seguem no histórico do git), bibliotecas com falhas conhecidas, Docker/Kubernetes/Terraform e pipelines de CI. Separa problema real de falso positivo, lista por prioridade, diz o que a automação não cobre e só então pergunta o que corrigir.

```text
/varredura-seguranca
/varredura-seguranca o ambiente de testes roda em http://localhost:3000 e está autorizado
```

Antes de consultar a internet sobre as bibliotecas (o banco público OSV recebe nome e versão de cada uma) ou de testar um endereço, o agente pede sua autorização. O resultado fica em `relatorio-seguranca/varredura.md`, pasta já ignorada pelo git. **Sem o atalho:**

O texto completo do comando vive em um só lugar, [`varredura-seguranca.md`](./.opencode/commands/varredura-seguranca.md). Em clientes sem atalhos, abra esse arquivo, copie o texto depois do cabeçalho `---` e troque `$ARGUMENTS` pelo seu pedido (ou apague, se for opcional).

### 5.5 Regras de segurança herdadas

Todas as skills compartilham limites que devem ser respeitados nos pedidos:

- defina escopo (repositório, componente, ambiente);
- testes ativos exigem autorização explícita — sem ela, análise estática e testes locais não intrusivos;
- dados sintéticos em testes; sem segredos ou dados pessoais em logs, relatórios e prompts;
- resultados classificados por evidência (confirmado, hipótese, fragilidade, falso positivo);
- valide com execução antes de declarar sucesso.

## 6. Bateria executável (`testes-vulnerabilidades`)

```bash
# Varredura completa com relatório consolidado (relatorio-seguranca/varredura.md)
python3 .opencode/skills/testes-vulnerabilidades/suite/varredura.py . --historico-git
#   + dependências no OSV e HTTP, somente com permissão:
python3 .opencode/skills/testes-vulnerabilidades/suite/varredura.py . --historico-git --osv \
  --url http://localhost:3000 --autorizado

# Estático — qualquer repositório, somente leitura, segredos mascarados
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py . --historico-git --json relatorio.json

# Dependências — inventário local; --osv consulta vulnerabilidades conhecidas
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_dependencias.py . --osv

# HTTP — apenas ambiente local/staging, exige declaração de autorização
python3 .opencode/skills/testes-vulnerabilidades/suite/verificacao_http.py \
  --url http://localhost:3000 --autorizado --json http.json
```

- **Orquestrador (`varredura.py`):** roda as camadas permitidas e gera `varredura.md`/`.json` com achados normalizados, matriz OWASP Top 10 e a lista do que não foi coberto.
- **Estático:** ~115 padrões (segredos, injeção SQL/comando/NoSQL/LDAP/SSTI, XSS, SSRF, redirect aberto, criptografia fraca, TLS desativado, sessão/CSRF, JWT, XXE, desserialização, traversal, IaC, Docker, Kubernetes, GitHub Actions, logs) e arquivos de credencial; `--historico-git` procura segredos já apagados. Achado = candidato, nunca vulnerabilidade automática.
- **Dependências:** lockfiles de npm/yarn/pnpm, PyPI, Go, RubyGems, Packagist, Cargo, Gradle, NuGet e SBOM; `--osv` consulta vulnerabilidades conhecidas (envia nome/versão ao serviço público OSV).
- **HTTP:** apenas GET/OPTIONS não destrutivos; cabeçalhos e qualidade da CSP, cookies, CORS, TLS, HTTP→HTTPS, arquivos/endpoints expostos, redirect aberto; recusa alvo sem `--autorizado`, recusa host fora de loopback/rede privada sem `--forcar-externo`, interrompe em 5xx.
- **Ferramentas externas (opcional):** com `--externas`, o orquestrador também roda gitleaks, semgrep e trivy quando instalados, consolidando tudo no mesmo relatório. Sem rede por padrão (`--externas-rede` libera atualização de base e regras; o código nunca é enviado), semgrep exige `--semgrep-config` e valores de segredo não são copiados.
- **Casos dinâmicos:** 12 especificações em `suite/casos/` (IDOR/tenants, sessão, injeção, XSS, SSRF, upload/desserialização, concorrência, exposição em erros/logs, ReDoS, abuso de API/lógica de negócio, XXE/SSTI, prompt injection) para implementar no framework de testes do projeto.
- **CI:** código de saída 1 a partir de `--falhar-em alta|media|baixa` (padrão `alta`); falsos positivos revisados via `--permitir`.
- **Testes da bateria:** `test_verificacao_estatica.py`, `test_verificacao_dependencias.py`, `test_verificacao_http.py`, `test_verificacao_externas.py` e `test_varredura.py` em `suite/` (sem rede externa); rode após alterar padrões ou checagens. A verificação estática é linha a linha: SQL em string de várias linhas não é detectado.

Detalhes de uso, allowlist e integração: [`suite/README.md`](./.opencode/skills/testes-vulnerabilidades/suite/README.md).

## 6.1 Evals das skills

[`.opencode/evals/`](./.opencode/evals/README.md) traz 11 casos que rodam um agente real num projeto temporário e conferem regras que nunca podem ser violadas (não vazar segredo, exigir autorização, não alterar arquivos em análise, tratar conteúdo do alvo como dado). `python3 .opencode/evals/rodar_evals.py --validar` confere os casos offline; para rodar com o agente, veja o README da pasta (usa a cota do seu LLM).

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
6. Ao adicionar skill nova: registre no índice e nas combinações de [`.opencode/skills/README.md`](./.opencode/skills/README.md). Os comandos das seções 5.2 e 5.3 não precisam mudar: eles não listam skills pelo nome.
7. O texto de cada comando vive só no arquivo do atalho ([`tarefa.md`](./.opencode/commands/tarefa.md), [`revisao-final.md`](./.opencode/commands/revisao-final.md) ou [`varredura-seguranca.md`](./.opencode/commands/varredura-seguranca.md), em `.opencode/commands/`); os READMEs apenas apontam para ele. Ao alterar um comando, edite só esse arquivo e repita a cópia para a instalação global, se usar uma (seção 3.3).
8. Ao mudar uma regra de segurança de uma skill, atualize ou acrescente o caso correspondente em [`.opencode/evals/casos.json`](./.opencode/evals/casos.json).
9. Antes de commitar, rode `python3 .opencode/skills/verificar_skills.py`: ele confere frontmatter, referências cruzadas, índices, links, contagens, a fonte única dos comandos, scripts citados que existem, orçamento de 9 KB por `SKILL.md` e travas de segurança (ex.: exigir autorização, nunca copiar valor de segredo) que não podem sumir ao enxugar uma skill.

## 9. Limitações

- Skills orientam o agente; **não substituem** requisitos do projeto, autorização formal para testes nem revisão humana.
- Ausência de achados da bateria não é prova de segurança — o relatório informa o que não foi coberto.
- As instruções são ponto de partida: adapte à stack, aos contratos e à política da organização.
