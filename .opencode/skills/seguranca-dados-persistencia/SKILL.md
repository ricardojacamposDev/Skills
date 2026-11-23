---
name: seguranca-dados-persistencia
description: Revisa e endurece a segurança da camada de dados — isolamento entre tenants no banco (inclusive row-level security do Postgres e serviços que expõem o banco por API), contas de banco com privilégio mínimo, consultas seguras, criptografia e mascaramento, backups, migrações e retenção. Use ao modelar ou migrar esquemas, configurar políticas de acesso, RLS, papéis e permissões de banco, revisar acesso a dados sensíveis ou multitenant, ou ao usar bancos gerenciados como Supabase, mesmo que o pedido seja apenas funcional.
---

# Segurança de dados e persistência

O banco é onde o dano se concentra: um filtro de tenant esquecido numa consulta, uma conta com privilégio demais ou uma tabela exposta sem política equivalem a vazamento em massa. Em serviços que expõem o banco diretamente por API (PostgREST, Supabase e similares), as políticas de linha são a única barreira entre o cliente e os dados. Revise o que está declarado (esquemas, migrações, políticas) e só consulte bancos em execução com autorização.

## 1. Mapeie dados e acessos

- Liste as tabelas e os campos sensíveis (pessoais, financeiros, credenciais, segredos) e a classificação de cada um.
- Liste **quem se conecta**: aplicação, jobs, ferramentas de BI, equipe, funções expostas e clientes que falam com o banco por API; e por qual caminho e credencial.
- Defina o modelo de tenancy (coluna de tenant, esquema ou banco por tenant) e onde a identidade do chamador entra no banco.

## 2. Isolamento entre tenants e políticas de linha

- Filtros de tenant só no código da aplicação são frágeis: um esquecimento vaza dados. Reforce no banco com políticas de linha.
- Postgres: habilite `ENABLE ROW LEVEL SECURITY` (e `FORCE` quando o dono da tabela também acessa pela aplicação) em toda tabela com dados de tenant ou de usuário; escreva políticas `USING` (leitura) e `WITH CHECK` (escrita) explícitas por operação. Tabela com RLS ativo e sem política nega tudo, e tabela sem RLS exposta é pública para quem tem acesso à API.
- A identidade do tenant vem de um contexto que o cliente não controla (claim verificada do token, variável de sessão definida por requisição); nunca de parâmetro, cabeçalho ou campo do corpo.
- Em serviços que expõem o banco por API: confira quais esquemas estão expostos, que a chave de serviço (que ignora RLS) nunca chega ao navegador nem ao aplicativo cliente, e que visões e funções (`SECURITY DEFINER`) não contornam as políticas.
- Teste sempre o isolamento com dois tenants, em leitura, inserção, atualização e exclusão.

## 3. Privilégio mínimo para contas e papéis

- Contas separadas para a aplicação em execução, para migrações e para análise; nada de superusuário nem conta compartilhada.
- Conceda por esquema e tabela apenas o necessário (`SELECT`, `INSERT`...), revogue o acesso público padrão e use réplicas somente leitura para BI.
- A conta da aplicação não cria nem altera objetos, não apaga backups e não administra papéis. Credenciais e rotação seguem `gestao-segredos`.

## 4. Consultas seguras

- Parametrize sempre; cuidado com consultas cruas do ORM, SQL dinâmico em funções e procedimentos e injeção de segunda ordem (dado salvo que depois entra numa consulta).
- Identificadores dinâmicos (tabela, coluna, ordenação) só por lista permitida; escape de curingas em `LIKE`; limite e paginação com teto.
- Registre consultas sem os valores sensíveis (`privacidade-dados`).

## 5. Criptografia e minimização

- TLS obrigatório na conexão, com verificação de certificado ligada; criptografia em repouso do disco e dos backups.
- Para campos de alto risco, criptografia por coluna com chaves fora do banco e gestão própria (`criptografia-aplicada`); hash de senhas em `autenticacao-identidade`.
- Dados reais não vão para desenvolvimento nem testes: use dados sintéticos ou mascarados de forma que resistam à reidentificação.

## 6. Backups, migrações e retenção

- Backups criptografados, com acesso separado da aplicação, protegidos contra exclusão pelo mesmo papel que os cria e com restauração testada.
- Migrações em etapas compatíveis (expandir, migrar, validar, remover) e revisadas também quanto a permissões, políticas e índices; uma migração que cria tabela sem política é um achado.
- Retenção e exclusão conforme a finalidade, propagando a réplicas, índices e backups com expiração definida (`privacidade-dados`); trilha de auditoria de acesso a dados críticos.

## 7. Prove com testes e evidência

- Testes de isolamento entre tenants e de política (tentativa de ler, inserir ou alterar fora do próprio tenant); consultas de verificação somente leitura, em desenvolvimento ou homologação, listando tabelas sem RLS, papéis e permissões concedidas.
- Consultar ou alterar um banco em execução exige autorização explícita, credencial somente leitura e ambiente definido; proponha mudanças como migração revisável, não como comando direto em produção.
- Não exiba valores de dados sensíveis nem credenciais; informe tabela, campo e política envolvidos.
- Classifique como vulnerabilidade (caminho concreto), fragilidade ou hardening, e informe o que não foi examinado.

## Formato de entrega

1. **Escopo e modelo de dados** — tabelas, dados sensíveis, tenancy e quem se conecta.
2. **Isolamento e acesso** — políticas, papéis e privilégios observados.
3. **Achados priorizados** — evidência, caminho de abuso, severidade e confiança.
4. **Correções e migrações** — mudanças propostas, ordem e reversão.
5. **Testes e riscos residuais** — casos executados, o que ficou sem verificação.

Exemplo preenchido e fictício, para calibrar o nível de detalhe: `exemplo-entrega.md` (nesta pasta); não copie os fatos.

Para a arquitetura e as migrações, use `arquitetura-aplicacoes-web`; para o isolamento visto nas rotas da API, `seguranca-apis`; para dados pessoais, `privacidade-dados`; para infraestrutura e redes, `seguranca-infraestrutura`; para segredos e credenciais, `gestao-segredos`; para criptografia, `criptografia-aplicada`.
