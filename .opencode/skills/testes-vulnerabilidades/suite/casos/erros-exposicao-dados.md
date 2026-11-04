# Caso dinâmico: erros, logs e exposição de dados

**Referências:** CWE-209, CWE-532, CWE-200, CWE-598 · OWASP A05/A09
**Camada:** integração/E2E com logs locais · **Pré-requisito:** ambiente local com logging ativo e dados sintéticos

## Objetivo

Verificar que respostas de erro, logs, exports e URLs não expõem segredos, dados pessoais de outros titulares nem informações internas.

## Pré-condições e dados sintéticos

- Contas sintéticas com dados marcadores únicos (`dado-ana-123`, `dado-beto-456`) e senha sintética; acesso aos logs do ambiente de teste.

## Procedimento

1. **Erro ao cliente:** force 404, 401, 403, 400 e um 500 (payload malformado previsto) e inspecione corpo/headers — sem stack trace, sem query SQL, sem versão de framework, sem caminho de servidor.
2. **Logs de erro:** repita as requisições e inspecione os logs do app — o 500 pode ter detalhe interno, mas nenhuma resposta ao cliente deve tê-los.
3. **Segredos em logs:** faça login e uma requisição autenticada; procure nos logs por senha, token, cookie de sessão e `Authorization` — não devem aparecer em claro.
4. **Marcadores em logs/exports:** como `ana`, gere operações que geram log/export (listagem, relatório, download); como `beto`, gere os dele; procure o marcador de `ana` em qualquer artefato acessível por `beto` e em logs compartilhados sem necessidade.
5. **URL:** verifique se tokens/senhas/dados pessoais não viajam em query string (logs de acesso e referers registram URLs completas).
6. **Headers/meta:** verifique ausência de banners de versão em respostas de API e páginas de erro.

## Resultado esperado (controle presente)

- Erros externos genéricos com correlação por ID de trace; segredos ausentes de logs; marcadores de outros titulares ausentes de exports/logs acessíveis; sem credenciais em query string.

## Resultado que caracteriza vulnerabilidade

- Stack trace/SQL na resposta; senha/token/cookie em log claro; export ou log acessível contendo dados de outro titular; credencial em query string.

## Evidência a registrar

- Corpos de erro coletados (mascarados), trechos de log relevantes sem valores reais e teste de regressão de filtragem de logs.

## Limites — não faça

- Use apenas marcadores sintéticos; ao encontrar segredo real em log, não o reproduza — registre local, volume e recomendação de rotação/limpeza.
