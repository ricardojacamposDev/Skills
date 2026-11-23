# Exemplo de entrega — `recursos-ia-generativa`

*Exemplo ilustrativo com dados fictícios, para calibrar o nível de detalhe e o formato. Não copie os fatos: cada entrega deve refletir o que foi realmente observado.*

1. **Objetivo e criticidade** — Assistente que resume chamados de suporte. Uso tolerante a erro (rascunho revisado por humano); a interface avisa que o texto pode conter imprecisões.

2. **Fluxo de dados** — Entra: texto do chamado (influenciável pelo cliente) e pelo menos um anexo. Sai: resumo exibido ao agente. Dados pessoais mínimos enviados ao provedor (sem anexos).

3. **Controles** — Conteúdo do chamado tratado como dado; saída validada por schema e codificada para HTML; nenhuma ferramenta exposta ao modelo; limite de tamanho e de custo por usuário.

4. **Avaliação** — 32 casos versionados (20 normais, 12 adversariais sintéticos, incluindo injeção indireta num anexo). Formato válido em 100%; 11 de 12 adversariais contidos; 1 caso falhou e virou regressão.

5. **Operação** — Versão do modelo e do prompt registrada por execução; logs sem conteúdo do chamado; painel de custo, latência e bloqueios.

6. **Riscos residuais** — O modelo pode omitir informação relevante no resumo; mitigado pela revisão humana. Caso adversarial falho ainda em correção.
