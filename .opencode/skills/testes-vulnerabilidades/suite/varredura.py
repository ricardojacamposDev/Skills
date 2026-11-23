#!/usr/bin/env python3
"""Varredura completa: executa as camadas da bateria e consolida um relatório.

  Camadas (cada uma só roda quando permitida):
    1. estática     — sempre (somente leitura); com --historico-git inclui segredos no histórico;
    2. dependências — inventário sempre; consulta ao OSV só com --osv (envia nome/versão
                      das dependências à API pública do OSV);
    3. HTTP         — só com --url e --autorizado (ambiente local/staging).

  Gera <saida>/varredura.json e <saida>/varredura.md com achados normalizados,
  matriz de cobertura OWASP Top 10 e a lista do que a varredura automática NÃO cobre.
  Achado de bateria é candidato: confirme alcançabilidade antes de classificar.
"""

import argparse
import datetime
import json
import os
import subprocess
import sys
from pathlib import Path

PASTA = Path(__file__).resolve().parent
SEVERIDADES = {"baixa": 0, "media": 1, "alta": 2}

OWASP = [
    ("A01", "Controle de acesso quebrado", {"TRAVERSAL", "REDIRECIONAMENTO", "CORS"},
     "casos/autorizacao-idor.md"),
    ("A02", "Falhas criptográficas", {"CRIPTOGRAFIA", "TRANSPORTE", "TLS"}, None),
    ("A03", "Injeção", {"INJECAO_SQL", "INJECAO_COMANDO", "XSS", "NOSQL", "LDAP", "SSTI", "GRAPHQL", "MEMORIA"},
     "casos/entrada-injecao.md, casos/saida-xss.md, casos/xml-templates.md"),
    ("A04", "Design inseguro", {"UPLOAD"},
     "casos/api-abuso-logica.md, casos/concorrencia-idempotencia.md"),
    ("A05", "Configuração incorreta", {"CONFIGURACAO", "CABECALHOS", "IAC", "XXE", "EXPOSICAO"}, None),
    ("A06", "Componentes vulneráveis", {"DEPENDENCIA"}, None),
    ("A07", "Falhas de identificação e autenticação", {"SESSAO", "JWT", "SEGREDO"},
     "casos/autenticacao-sessao.md"),
    ("A08", "Integridade de software e dados", {"DESSERIALIZACAO", "CI_CD", "CADEIA_SUPRIMENTOS", "PROTOTYPE_POLLUTION"},
     "casos/upload-desserializacao.md"),
    ("A09", "Falhas de log e monitoramento", {"LOGS"}, "casos/erros-exposicao-dados.md"),
    ("A10", "SSRF", {"SSRF"}, "casos/ssrf-redirecionamento.md"),
]

NAO_COBERTO = [
    "Autorização por objeto/tenant (IDOR/BOLA) e escalada de privilégio — exige casos dinâmicos com contas sintéticas.",
    "Lógica de negócio, limites de taxa, força bruta e atribuição em massa — `casos/api-abuso-logica.md`.",
    "Condições de corrida e idempotência — `casos/concorrencia-idempotencia.md`.",
    "Fluxos que só existem após login (a camada HTTP vê apenas rotas públicas).",
    "Código montado em várias linhas, fluxo de dados entre arquivos e frameworks não listados (análise é linha a linha).",
    "Vulnerabilidades de dia zero e dependências sem lockfile/SBOM; imagens de contêiner e pacotes do sistema operacional.",
    "Configuração real da nuvem/cluster em execução (a bateria lê apenas arquivos IaC versionados).",
    "Funcionalidades com IA generativa (prompt injection) — `casos/ia-prompt-injection.md`.",
]


def rodar(comando):
    processo = subprocess.run(comando, capture_output=True, text=True)
    return processo.returncode, processo.stdout, processo.stderr


def ler_json(caminho):
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def normalizar(camada, achado):
    local = achado.get("arquivo") or achado.get("local") or ""
    if achado.get("linha"):
        local = f"{local}:{achado['linha']}"
    return dict(
        camada=camada, categoria=achado.get("categoria", ""), id=achado.get("id") or "",
        titulo=achado.get("titulo", ""), severidade=achado.get("severidade", "baixa"),
        confianca=achado.get("confianca", "baixa"), cwe=achado.get("cwe", ""), local=local,
        evidencia=achado.get("trecho") or achado.get("detalhe") or "", acao=achado.get("acao", ""),
        estado="hipótese",
    )


def celula(texto, limite=90):
    texto = str(texto).replace("|", "\\|").replace("\n", " ")
    return texto if len(texto) <= limite else texto[:limite - 1] + "…"


def gerar_markdown(relatorio):
    linhas = ["# Relatório de varredura de segurança", ""]
    linhas.append(f"- Gerado em: {relatorio['gerado_em']}")
    linhas.append(f"- Alvo: `{relatorio['alvo']}`")
    linhas.append("- Cada achado é **candidato** (estado inicial: hipótese). Confirme alcançabilidade e impacto "
                  "antes de classificar como confirmado, fragilidade ou falso positivo.")
    linhas += ["", "## Camadas", "", "| Camada | Situação | Detalhe |", "|---|---|---|"]
    for nome, info in relatorio["camadas"].items():
        linhas.append(f"| {nome} | {info['situacao']} | {celula(info.get('detalhe', ''), 140)} |")
    r = relatorio["resumo"]
    linhas += ["", "## Resumo", "",
               f"Total: **{r['total']}** — alta: {r['por_severidade']['alta']}, média: {r['por_severidade']['media']}, "
               f"baixa: {r['por_severidade']['baixa']}", ""]
    for severidade in ("alta", "media", "baixa"):
        itens = [a for a in relatorio["achados"] if a["severidade"] == severidade]
        if not itens:
            continue
        rotulo = {"alta": "Alta", "media": "Média", "baixa": "Baixa"}[severidade]
        linhas += [f"## Severidade {rotulo} ({len(itens)})", "",
                   "| Camada | Categoria/id | Título | Local | Confiança | Evidência |", "|---|---|---|---|---|---|"]
        for a in itens:
            linhas.append(f"| {a['camada']} | {a['categoria']}/{celula(a['id'], 40)} | {celula(a['titulo'], 70)} | "
                          f"`{celula(a['local'], 60)}` | {a['confianca']} | {celula(a['evidencia'], 80)} |")
        linhas.append("")
    linhas += ["## Cobertura OWASP Top 10 (2021)", "",
               "| Item | Achados | Verificação automática | Casos dinâmicos a implementar |", "|---|---|---|---|"]
    for item in relatorio["cobertura"]:
        linhas.append(f"| {item['codigo']} {item['nome']} | {item['achados']} | {item['automatica']} | "
                      f"{item['casos'] or '—'} |")
    linhas += ["", "## Não coberto pela varredura automática", ""]
    linhas += [f"- {t}" for t in NAO_COBERTO]
    linhas += ["", "## Próximos passos", "",
               "1. Triar cada achado lendo o código/rota e registrar o estado (confirmado, hipótese, fragilidade, falso positivo).",
               "2. Falsos positivos: registrar com justificativa no arquivo de `--permitir`.",
               "3. Segredos: rotacionar pelo fluxo autorizado (`gestao-segredos`); nunca copiar o valor.",
               "4. Corrigir pela causa raiz com teste de regressão (`resposta-vulnerabilidades`) e rerodar a varredura.",
               "5. Implementar os casos dinâmicos aplicáveis para as classes não cobertas.", ""]
    return "\n".join(linhas)


def principal(argv=None):
    parser = argparse.ArgumentParser(description="Varredura completa de segurança com relatório consolidado.")
    parser.add_argument("alvo", help="diretório do projeto")
    parser.add_argument("--saida", default="relatorio-seguranca", help="pasta dos relatórios (padrão: relatorio-seguranca)")
    parser.add_argument("--historico-git", action="store_true", help="procura segredos também no histórico git")
    parser.add_argument("--osv", action="store_true",
                        help="consulta vulnerabilidades conhecidas no OSV (envia nome/versão das dependências)")
    parser.add_argument("--cache-osv", help="arquivo de cache das consultas ao OSV")
    parser.add_argument("--url", help="URL do ambiente local/staging para a camada HTTP")
    parser.add_argument("--autorizado", action="store_true", help="declara autorização para a camada HTTP")
    parser.add_argument("--espera-http", type=float, default=0.5, help="segundos entre requisições HTTP (padrão: 0.5)")
    parser.add_argument("--forcar-externo", action="store_true", help="repassa ao verificador HTTP (alvo não local)")
    parser.add_argument("--permitir", help="arquivo de exceções revisadas da camada estática")
    parser.add_argument("--falhar-em", choices=["alta", "media", "baixa", "qualquer", "nunca"], default="alta")
    args = parser.parse_args(argv)

    if not Path(args.alvo).is_dir():
        print(f"erro: {args.alvo} não é um diretório", file=sys.stderr)
        return 2
    saida = Path(args.saida)
    saida.mkdir(parents=True, exist_ok=True)
    # Relatórios citam trechos de código e locais de segredos: fora do git por padrão.
    ignorar = saida / ".gitignore"
    if not ignorar.exists():
        ignorar.write_text("*\n", encoding="utf-8")
    py = sys.executable
    camadas, achados, erro_camada = {}, [], False

    # 1. Estática
    destino = saida / "estatica.json"
    cmd = [py, str(PASTA / "verificacao_estatica.py"), args.alvo, "--json", str(destino),
           "--falhar-em", "nunca", "--resumo"]
    if args.historico_git:
        cmd.append("--historico-git")
    if args.permitir:
        cmd += ["--permitir", args.permitir]
    codigo, _, erro = rodar(cmd)
    dados = ler_json(destino)
    if codigo == 0 and dados:
        achados += [normalizar("estática", a) for a in dados["achados"]]
        detalhe = f"{dados['resumo']['arquivos']} arquivos"
        if args.historico_git:
            commits = dados["resumo"].get("commits_historico") or 0
            detalhe += (f"; histórico git: {commits} commits" if commits
                        else "; histórico git NÃO lido (alvo fora da raiz de um repositório, repositório vazio ou erro do git — "
                         "rode verificacao_estatica.py --historico-git para ver o aviso)")
        pulos = dados["resumo"].get("puladas") or {}
        if pulos.get("arquivos_grandes"):
            detalhe += f"; ATENÇÃO: {pulos['arquivos_grandes']} arquivo(s) acima de {pulos['limite_bytes']} bytes NÃO analisados"
        if pulos.get("linhas_longas_historico"):
            detalhe += (f"; ATENÇÃO: {pulos['linhas_longas_historico']} linha(s) do histórico acima de "
                        f"{pulos['limite_linha_historico']} caracteres NÃO analisadas")
        camadas["estática"] = dict(situacao="executada", detalhe=detalhe)
    else:
        erro_camada = True
        camadas["estática"] = dict(situacao="erro", detalhe=erro.strip()[:200])

    # 2. Dependências
    destino = saida / "dependencias.json"
    cmd = [py, str(PASTA / "verificacao_dependencias.py"), args.alvo, "--json", str(destino),
           "--falhar-em", "nunca", "--resumo"]
    if args.osv:
        cmd.append("--osv")
        if args.cache_osv:
            cmd += ["--cache", args.cache_osv]
    codigo, _, erro = rodar(cmd)
    dados = ler_json(destino)
    if codigo == 0 and dados:
        achados += [normalizar("dependências", a) for a in dados["achados"]]
        ecos = ", ".join(f"{k}: {v}" for k, v in sorted(dados["resumo"].get("por_ecossistema", {}).items()))
        if args.osv:
            situacao = "executada"
            detalhe = f"{dados['resumo']['pacotes']} pacotes consultados no OSV ({ecos or 'nenhum lockfile'})"
        else:
            situacao = "só inventário"
            detalhe = (f"{dados['resumo']['pacotes']} pacotes ({ecos or 'nenhum lockfile'}); sem --osv, "
                       "vulnerabilidades conhecidas NÃO foram consultadas")
        camadas["dependências"] = dict(situacao=situacao, detalhe=detalhe)
    else:
        erro_camada = True
        camadas["dependências"] = dict(situacao="erro", detalhe=erro.strip()[:200] or "falha na consulta")

    # 3. HTTP
    if not args.url:
        camadas["HTTP"] = dict(situacao="não executada", detalhe="sem --url (informe um ambiente local/staging)")
    elif not args.autorizado:
        camadas["HTTP"] = dict(situacao="não executada", detalhe="sem --autorizado: exige autorização explícita")
    else:
        destino = saida / "http.json"
        cmd = [py, str(PASTA / "verificacao_http.py"), "--url", args.url, "--autorizado", "--json", str(destino),
               "--sem-cor", "--espera", str(args.espera_http)]
        if args.forcar_externo:
            cmd.append("--forcar-externo")
        codigo, saida_http, erro = rodar(cmd)
        dados = ler_json(destino)
        if codigo in (0, 1) and dados:
            achados += [normalizar("HTTP", a) for a in dados["achados"]]
            detalhe = f"{dados['requisicoes']} requisições GET/OPTIONS em {args.url}"
            if dados.get("interrompido"):
                detalhe += f"; INTERROMPIDA: {dados['interrompido']}"
            camadas["HTTP"] = dict(situacao="executada", detalhe=detalhe)
        else:
            erro_camada = True
            mensagem = (erro or saida_http).strip().splitlines()
            camadas["HTTP"] = dict(situacao="erro/recusa", detalhe=(mensagem[0] if mensagem else "")[:200])

    achados.sort(key=lambda a: (-SEVERIDADES.get(a["severidade"], 0), -SEVERIDADES.get(a["confianca"], 0),
                                a["camada"], a["local"]))
    por_severidade = {"alta": 0, "media": 0, "baixa": 0}
    for a in achados:
        por_severidade[a["severidade"]] = por_severidade.get(a["severidade"], 0) + 1

    executadas = {nome for nome, info in camadas.items() if info["situacao"] == "executada"}
    cobertura = []
    for codigo_owasp, nome, categorias, casos in OWASP:
        total = sum(1 for a in achados if a["categoria"] in categorias)
        if codigo_owasp == "A06":
            automatica = "sim (OSV)" if "dependências" in executadas else "não (rode com --osv)"
        elif codigo_owasp == "A04":
            automatica = "parcial (upload)"
        else:
            automatica = "parcial"
        cobertura.append(dict(codigo=codigo_owasp, nome=nome, achados=total, automatica=automatica, casos=casos))

    relatorio = dict(
        ferramenta="varredura", versao="1.0",
        gerado_em=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        alvo=os.path.abspath(args.alvo), camadas=camadas,
        resumo=dict(total=len(achados), por_severidade=por_severidade),
        achados=achados, cobertura=cobertura, nao_coberto=NAO_COBERTO,
    )
    with open(saida / "varredura.json", "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2)
    with open(saida / "varredura.md", "w", encoding="utf-8") as f:
        f.write(gerar_markdown(relatorio))

    print("Varredura de segurança — resumo")
    for nome, info in camadas.items():
        print(f"  {nome}: {info['situacao']} — {info.get('detalhe', '')}")
    print(f"Achados: {len(achados)} (alta: {por_severidade['alta']}, média: {por_severidade['media']}, "
          f"baixa: {por_severidade['baixa']})")
    print(f"Relatórios: {saida / 'varredura.md'} e {saida / 'varredura.json'}")
    print("Lembrete: a pasta de relatórios tem .gitignore próprio; revise antes de compartilhar.")

    if erro_camada:
        return 2
    if args.falhar_em != "nunca":
        limite = {"alta": 2, "media": 1, "baixa": 0, "qualquer": 0}[args.falhar_em]
        if any(SEVERIDADES[a["severidade"]] >= limite for a in achados):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(principal())
