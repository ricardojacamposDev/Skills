#!/usr/bin/env python3
"""Verificação de dependências (SCA) contra o banco público OSV.

  Inventaria pacotes a partir de lockfiles/SBOM e, com --osv, consulta
  https://api.osv.dev/v1/querybatch para identificar vulnerabilidades
  conhecidas. Somente leitura: não executa código do alvo.

  Privacidade: o modo --osv envia nome, ecossistema e versão das dependências
  (que já constam no lockfile) para a API pública do OSV, operada pelo Google.
  Não envia caminhos, conteúdo de arquivos nem qualquer dado do projeto. Sem
  --osv, o script apenas inventaria, sem tráfego de rede.

  Cada achado é um candidato: a aplicabilidade depende do artefato implantado e
  do alcance do código vulnerável (confirme com `pesquisa-vulnerabilidades`).
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEVERIDADES = {"baixa": 0, "media": 1, "alta": 2}
CONFIANCAS = {"baixa": 0, "media": 1, "alta": 2}
OSV_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
LOTE_MAXIMO = 500

# Parseadores por nome de arquivo. Cada um retorna (ecossistema, nome, versão, linha).
# Ecossistemas seguem a nomenclatura do OSV.
EXTENSOES_IGNORADAS = (".md", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff",
                       ".woff2", ".ico", ".pdf", ".map", ".min.js", ".min.css")


def _versao_limpa(versao):
    if not isinstance(versao, str):
        return None
    bruto = versao.strip().strip("'\"")
    bruto = re.sub(r"^[=vV]+\s*", "", bruto)
    bruto = re.sub(r"[<>=~^ ].*$", "", bruto)
    bruto = bruto.strip()
    return bruto or None


def _npm_nome(chave):
    """Extrai o nome de um caminho de pacote npm (`node_modules/@a/b`)."""
    nome = re.sub(r"^.*node_modules/", "", chave)
    if not nome:
        return None
    partes = nome.split("node_modules/")
    nome = partes[-1]
    return nome or None


def parse_package_lock(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    if isinstance(dados.get("packages"), dict):
        for chave, info in dados["packages"].items():
            if not isinstance(info, dict):
                continue
            nome = _npm_nome(chave)
            versao = _versao_limpa(info.get("version"))
            if nome and versao and nome != "":
                pacotes.append(("npm", nome, versao))
    if not pacotes and isinstance(dados.get("dependencies"), dict):
        pilha = list(dados["dependencies"].items())
        while pilha:
            nome, info = pilha.pop()
            if not isinstance(info, dict):
                continue
            versao = _versao_limpa(info.get("version"))
            if nome and versao:
                pacotes.append(("npm", nome, versao))
            if isinstance(info.get("dependencies"), dict):
                pilha.extend(info["dependencies"].items())
    return pacotes


def parse_yarn_lock(caminho):
    pacotes = []
    nome = None
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            if linha.startswith("#") or not linha.strip():
                continue
            if not linha.startswith((" ", "\t")) and linha.rstrip().endswith(":"):
                chave = linha.strip()[:-1].strip().strip("'\"")
                primeira = re.split(r",\s*", chave)[0].strip().strip("'\"")
                if primeira.startswith("@"):
                    m = re.match(r"(@[^@/]+/[^@]+)@", primeira)
                else:
                    m = re.match(r"([^@]+)@", primeira)
                nome = m.group(1) if m else None
                continue
            m = re.search(r'^\s*version\s+"?([^"\s]+)"?', linha)
            if m and nome:
                versao = _versao_limpa(m.group(1))
                if versao:
                    pacotes.append(("npm", nome, versao))
                nome = None
    return pacotes


def parse_pnpm_lock(caminho):
    """Parser simplificado de pnpm-lock.yaml (pacotes em `packages:`)."""
    pacotes = []
    em_pacotes = False
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            if re.match(r"^packages:\s*$", linha):
                em_pacotes = True
                continue
            if em_pacotes and linha and not linha.startswith((" ", "\t")):
                em_pacotes = False
            if not em_pacotes:
                continue
            m = re.match(r"""^\s+['"]?/?(@?[^@\s:/'"]+(?:/[^@\s:/'"]+)?)@(\d[^:\s'"(]*)""", linha)
            if m:
                nome = m.group(1)
                versao = _versao_limpa(m.group(2))
                if nome and versao:
                    pacotes.append(("npm", nome, versao))
    return pacotes


def parse_requirements(caminho):
    pacotes = []
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            bruto = linha.split("#", 1)[0].strip()
            if not bruto or bruto.startswith(("-", "git+", "http://", "https://")):
                continue
            bruto = bruto.split(";", 1)[0].strip()  # remove marcadores de ambiente
            m = re.match(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*===?\s*([A-Za-z0-9_.\-+!]+)$", bruto)
            if m:
                pacotes.append(("PyPI", m.group(1), _versao_limpa(m.group(2))))
    return pacotes


def _parse_toml_packages(caminho, ecossistema):
    """Parser mínimo de `[[package]]` com name/version (poetry.lock, Cargo.lock)."""
    pacotes = []
    nome = None
    versao = None
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            if re.match(r"^\s*\[\[?package\]?\]\s*$", linha):
                if nome and versao:
                    pacotes.append((ecossistema, nome, versao))
                nome, versao = None, None
                continue
            m = re.match(r'^\s*name\s*=\s*"([^"]+)"', linha)
            if m:
                nome = m.group(1)
            m = re.match(r'^\s*version\s*=\s*"([^"]+)"', linha)
            if m:
                versao = _versao_limpa(m.group(1))
    if nome and versao:
        pacotes.append((ecossistema, nome, versao))
    return pacotes


def parse_pipfile_lock(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    for secao in ("default", "develop"):
        itens = dados.get(secao)
        if not isinstance(itens, dict):
            continue
        for nome, info in itens.items():
            if not isinstance(info, dict):
                continue
            versao = info.get("version")
            if isinstance(versao, str) and versao.startswith("=="):
                versao = _versao_limpa(versao)
                if versao:
                    pacotes.append(("PyPI", nome, versao))
    return pacotes


def parse_gemfile_lock(caminho):
    pacotes = []
    secao = None
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            if re.match(r"^[A-Z][A-Z0-9_]*\s*$", linha.strip()) and not linha.startswith(" "):
                secao = linha.strip()
                continue
            if secao not in ("GEM", "PATH", "GIT"):
                continue
            m = re.match(r"^\s{4}([A-Za-z0-9_\-\.]+)\s+\(([^)]+)\)", linha)
            if m:
                versao = _versao_limpa(m.group(2))
                if versao:
                    pacotes.append(("RubyGems", m.group(1), versao))
    return pacotes


def parse_go_sum(caminho):
    pacotes = []
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            partes = linha.split()
            if len(partes) < 2:
                continue
            modulo, versao = partes[0], partes[1]
            if versao.endswith("/go.mod"):
                continue
            versao = _versao_limpa(versao)
            if modulo and versao:
                pacotes.append(("Go", modulo, versao))
    return pacotes


def parse_composer_lock(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    for secao in ("packages", "packages-dev"):
        for item in dados.get(secao, []) or []:
            if not isinstance(item, dict):
                continue
            nome = item.get("name")
            versao = _versao_limpa(item.get("version"))
            if nome and versao:
                pacotes.append(("Packagist", nome, versao))
    return pacotes


def parse_gradle_lockfile(caminho):
    pacotes = []
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        for linha in f:
            m = re.match(r"^([\w.\-]+):([\w.\-]+):([^=\s]+)=", linha.strip())
            if m:
                pacotes.append(("Maven", f"{m.group(1)}:{m.group(2)}", m.group(3)))
    return pacotes


def parse_nuget_lock(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    for alvo in (dados.get("dependencies") or {}).values():
        if not isinstance(alvo, dict):
            continue
        for nome, info in alvo.items():
            if isinstance(info, dict) and info.get("type") != "Project":
                versao = _versao_limpa(info.get("resolved"))
                if versao:
                    pacotes.append(("NuGet", nome, versao))
    return pacotes


def _purl_para_pacote(purl):
    """Deriva (ecossistema, nome, versão) de um purl, quando possível."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    corpo = purl[4:]
    tipo, resto = (corpo.split("/", 1) + [""])[:2] if "/" in corpo else (corpo, "")
    resto = resto.split("?", 1)[0].split("#", 1)[0]
    versao = None
    if "@" in resto:
        resto, versao = resto.rsplit("@", 1)
    nome = urllib.parse.unquote(resto)
    ecos = {
        "npm": "npm", "pypi": "PyPI", "golang": "Go", "gem": "RubyGems",
        "composer": "Packagist", "cargo": "crates.io", "nuget": "NuGet", "maven": "Maven",
    }
    eco = ecos.get(tipo.lower())
    if eco == "Maven" and "/" in nome:
        nome = nome.replace("/", ":", 1)  # pkg:maven/grupo/artefato -> grupo:artefato
    if not eco or not nome:
        return None
    versao = _versao_limpa(versao)
    if not versao:
        return None
    return eco, nome, versao


def parse_cyclonedx(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    for item in dados.get("components", []) or []:
        if not isinstance(item, dict):
            continue
        purl = item.get("purl")
        derivado = _purl_para_pacote(purl)
        # Sem purl o ecossistema é desconhecido: não adivinhar (consulta errada geraria falso negativo).
        if derivado:
            pacotes.append(derivado)
    return pacotes


def parse_spdx(caminho):
    with open(caminho, "r", encoding="utf-8", errors="replace") as f:
        dados = json.load(f)
    pacotes = []
    for item in dados.get("packages", []) or []:
        if not isinstance(item, dict):
            continue
        nome = item.get("name")
        versao = _versao_limpa(item.get("versionInfo"))
        ecos = None
        for ref in item.get("externalRefs", []) or []:
            if ref.get("referenceType") == "purl":
                ecos = _purl_para_pacote(ref.get("referenceLocator"))
                break
        if ecos:
            pacotes.append(ecos)
    return pacotes


PARSEADORES = [
    ("package-lock.json", parse_package_lock),
    ("npm-shrinkwrap.json", parse_package_lock),
    ("yarn.lock", parse_yarn_lock),
    ("pnpm-lock.yaml", parse_pnpm_lock),
    ("requirements.txt", parse_requirements),
    ("poetry.lock", lambda p: _parse_toml_packages(p, "PyPI")),
    ("Pipfile.lock", parse_pipfile_lock),
    ("Gemfile.lock", parse_gemfile_lock),
    ("go.sum", parse_go_sum),
    ("composer.lock", parse_composer_lock),
    ("Cargo.lock", lambda p: _parse_toml_packages(p, "crates.io")),
    ("gradle.lockfile", parse_gradle_lockfile),
    ("packages.lock.json", parse_nuget_lock),
]


def inventariar(alvos):
    """Retorna lista de dicts com ecossistema, nome, versão e origem."""
    encontrados = []
    for alvo in alvos:
        caminhos = []
        if os.path.isfile(alvo):
            caminhos.append(alvo)
        elif os.path.isdir(alvo):
            for raiz, diretorios, nomes in os.walk(alvo):
                diretorios[:] = [d for d in diretorios if d not in (
                    "node_modules", ".git", ".venv", "venv", "env", "vendor",
                    "target", "dist", "build", ".cache", "__pycache__", "site-packages")]
                for nome in nomes:
                    if not os.path.islink(os.path.join(raiz, nome)):  # symlink pode apontar para fora do escopo
                        caminhos.append(os.path.join(raiz, nome))
        else:
            print(f"aviso: alvo inexistente ignorado: {alvo}", file=sys.stderr)
            continue
        for caminho in caminhos:
            nome_arquivo = os.path.basename(caminho)
            if nome_arquivo in dict(PARSEADORES):
                parseador = dict(PARSEADORES)[nome_arquivo]
            elif nome_arquivo.endswith((".cdx.json", ".spdx.json")) or nome_arquivo in ("bom.json", "sbom.json"):
                parseador = parse_spdx if nome_arquivo.endswith(".spdx.json") else parse_cyclonedx
            else:
                continue
            if parseador is None:
                continue
            try:
                pacotes = parseador(caminho)
            except Exception:  # lockfile malformado/hostil (JSON de outro tipo, aninhamento profundo) não derruba a varredura
                print(f"aviso: não foi possível interpretar {caminho}", file=sys.stderr)
                continue
            for eco, nome, versao in pacotes:
                encontrados.append(dict(ecossistema=eco, nome=nome, versao=versao,
                                        arquivo=os.path.relpath(caminho, alvo)
                                        if os.path.isdir(alvo) else caminho))
    # Deduplica por (ecossistema, nome, versão)
    vistos = set()
    inventario = []
    for p in encontrados:
        chave = (p["ecossistema"], p["nome"].lower(), p["versao"])
        if chave in vistos:
            continue
        vistos.add(chave)
        inventario.append(p)
    return inventario


# --- CVSS v3 (base score) -------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def cvss3_base_score(vetor):
    """Calcula o base score CVSS v3.x de um vetor; None se incompleto."""
    if not isinstance(vetor, str) or not vetor.upper().startswith("CVSS:3"):
        return None
    metricas = dict(re.findall(r"/([A-Z]{1,3}):([A-Z])", vetor.upper()))
    try:
        av = _AV[metricas["AV"]]
        ac = _AC[metricas["AC"]]
        ui = _UI[metricas["UI"]]
        c = _CIA[metricas["C"]]
        i = _CIA[metricas["I"]]
        a = _CIA[metricas["A"]]
    except KeyError:
        return None
    escopo = metricas.get("S", "U")
    if escopo not in ("U", "C"):
        return None
    if metricas["PR"] == "N":
        pr = 0.85
    elif metricas["PR"] == "L":
        pr = 0.68 if escopo == "C" else 0.62
    elif metricas["PR"] == "H":
        pr = 0.5 if escopo == "C" else 0.27
    else:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    if escopo == "U":
        impacto = 6.42 * iss
    else:
        impacto = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    if impacto <= 0:
        return 0.0
    explorabilidade = 8.22 * av * ac * pr * ui
    if escopo == "U":
        base = min(impacto + explorabilidade, 10.0)
    else:
        base = min(1.08 * (impacto + explorabilidade), 10.0)
    return round(base, 1)


def severidade_de_vuln(vuln):
    """Retorna (severidade, confianca, score) a partir do registro OSV."""
    db = (vuln.get("database_specific") or {})
    bruto = str(db.get("severity") or "").upper()
    if bruto in ("CRITICAL",):
        return "alta", "alta", 9.8
    if bruto in ("HIGH",):
        return "alta", "alta", 8.5
    if bruto in ("MODERATE", "MEDIUM"):
        return "media", "media", 5.5
    if bruto in ("LOW",):
        return "baixa", "media", 2.0
    for item in vuln.get("severity", []) or []:
        if item.get("type") in ("CVSS_V3", "CVSS_V31", "CVSS_V30"):
            score = cvss3_base_score(item.get("score", ""))
            if score is None:
                continue
            if score >= 7.0:
                return "alta", "media", score
            if score >= 4.0:
                return "media", "media", score
            return "baixa", "media", score
    return "media", "baixa", None


def _versao_corrigida(vuln, nome=None, ecossistema=None):
    afetados = vuln.get("affected", []) or []
    if nome:
        # Um advisory pode cobrir vários pacotes; prefira a entrada do pacote inventariado.
        do_pacote = [a for a in afetados
                     if (a.get("package") or {}).get("name", "").lower() == nome.lower()
                     and (not ecossistema or (a.get("package") or {}).get("ecosystem", ecossistema) == ecossistema)]
        afetados = do_pacote or afetados
    for afetado in afetados:
        for intervalo in afetado.get("ranges", []) or []:
            for evento in intervalo.get("events", []) or []:
                if evento.get("fixed"):
                    return evento["fixed"]
    return None


def _post_osv(consultas, timeout, user_agent):
    """Envia um lote ao OSV. Retorna o JSON de resposta."""
    corpo = json.dumps({"queries": consultas}).encode("utf-8")
    pedido = urllib.request.Request(
        OSV_URL, data=corpo, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": user_agent},
    )
    with urllib.request.urlopen(pedido, timeout=timeout) as resposta:
        return json.loads(resposta.read().decode("utf-8", errors="replace"))


def _get_vuln(identificador, timeout, user_agent):
    """Busca o registro completo de uma vulnerabilidade (o querybatch só devolve id)."""
    pedido = urllib.request.Request(
        OSV_VULN_URL + urllib.parse.quote(identificador, safe=""),
        headers={"User-Agent": user_agent})
    with urllib.request.urlopen(pedido, timeout=timeout) as resposta:
        return json.loads(resposta.read().decode("utf-8", errors="replace"))


CAMPOS_DETALHE = ("summary", "details", "affected", "severity", "database_specific", "aliases")


def _detalhar(vulns, detalhes, timeout, espera, user_agent):
    """Completa registros resumidos ({id, modified}) com o registro completo do OSV."""
    completos = []
    for vuln in vulns:
        if any(campo in vuln for campo in CAMPOS_DETALHE):
            completos.append(vuln)
            continue
        identificador = vuln.get("id")
        if not identificador:
            continue
        if identificador not in detalhes:
            try:
                detalhes[identificador] = _get_vuln(identificador, timeout, user_agent)
            except (urllib.error.URLError, OSError, ValueError) as e:
                raise RuntimeError(f"falha ao detalhar {identificador} no OSV: {e}") from e
            if espera:
                time.sleep(espera / 4)
        completos.append(detalhes[identificador])
    return completos


def _carregar_cache(caminho):
    if not caminho or not os.path.exists(caminho):
        return {}
    try:
        with open(caminho, "r", encoding="utf-8") as f:
            dados = json.load(f)
        return dados.get("entradas", {}) if isinstance(dados, dict) else {}
    except (OSError, ValueError):
        return {}


def _gravar_cache(caminho, entradas):
    if not caminho:
        return
    try:
        with open(caminho, "w", encoding="utf-8") as f:
            json.dump({"versao": 1, "gerado_em": datetime.datetime.now(
                datetime.timezone.utc).isoformat(), "entradas": entradas}, f, ensure_ascii=False)
    except OSError as e:
        print(f"aviso: não foi possível gravar cache: {e}", file=sys.stderr)


def consultar_osv(inventario, cache=None, timeout=15.0, espera=0.2, user_agent="bateria-vulnerabilidades/1.0"):
    """Consulta o OSV para cada pacote. Retorna {índice: lista de vulns}."""
    entradas = _carregar_cache(cache) if cache else {}
    detalhes = {}
    agora = time.time()
    ttl = 24 * 3600
    consultas, indices, pendentes = [], [], []
    for indice, p in enumerate(inventario):
        chave = f"{p['ecossistema']}|{p['nome'].lower()}|{p['versao']}"
        cached = entradas.get(chave)
        if cached and (agora - cached.get("ts", 0)) < ttl:
            indices.append(indice)
            pendentes.append(cached.get("vulns", []))
            continue
        consultas.append({"package": {"name": p["nome"], "ecosystem": p["ecossistema"]},
                          "version": p["versao"]})
        indices.append(indice)
        pendentes.append(None)
    resultados = {}
    for inicio in range(0, len(consultas), LOTE_MAXIMO):
        lote = consultas[inicio:inicio + LOTE_MAXIMO]
        try:
            resposta = _post_osv(lote, timeout, user_agent)
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise RuntimeError(f"falha ao consultar o OSV: {e}") from e
        for consulta, resultado in zip(lote, resposta.get("results", [])):
            chave = f"{consulta['package']['ecosystem']}|{consulta['package']['name'].lower()}|{consulta['version']}"
            resultados[chave] = _detalhar(resultado.get("vulns", []) or [], detalhes, timeout, espera, user_agent)
        if espera:
            time.sleep(espera)
    finais = {}
    for indice, vulns in zip(indices, pendentes):
        p = inventario[indice]
        if vulns is None:
            chave = f"{p['ecossistema']}|{p['nome'].lower()}|{p['versao']}"
            vulns = resultados.get(chave, [])
            entradas[chave] = {"ts": agora, "vulns": vulns}
        finais[indice] = vulns
    if cache:
        _gravar_cache(cache, entradas)
    return finais


def construir_achados(inventario, vulnerabilidades):
    achados = []
    for indice, vulns in vulnerabilidades.items():
        p = inventario[int(indice)]
        for vuln in vulns:
            severidade, confianca, score = severidade_de_vuln(vuln)
            identificadores = [vuln.get("id", "?")] + [
                a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")]
            corrigida = _versao_corrigida(vuln, p["nome"], p["ecossistema"])
            resumo = (vuln.get("summary") or identificadores[0] or "vulnerabilidade conhecida")
            resumo = re.sub(r"\s+", " ", resumo)[:200]
            acao = (f"Atualize {p['nome']} para {corrigida} ou versão corrigida pelo fornecedor."
                    if corrigida else
                    f"Verifique advisory {identificadores[0]} e atualize {p['nome']} para versão corrigida.")
            achados.append(dict(
                categoria="DEPENDENCIA", id=identificadores[0], titulo=resumo,
                severidade=severidade, confianca=confianca, cwe="",
                arquivo=p["arquivo"], linha=0,
                trecho=f"{p['ecossistema']}:{p['nome']}@{p['versao']}"
                       + (f" (CVSS {score})" if score is not None else "")
                       + (" | " + ", ".join(identificadores[:3]) if len(identificadores) > 1 else ""),
                acao=acao,
            ))
    return achados


def ordenar(achados):
    return sorted(achados, key=lambda a: (-SEVERIDADES[a["severidade"]],
                                         -CONFIANCAS[a["confianca"]], a["arquivo"], a["id"]))


def cor(texto, codigo, ativo):
    return f"\033[{codigo}m{texto}\033[0m" if ativo else texto


def imprimir(achados, stats, ativo_cor):
    mapa_cor = {"alta": "31", "media": "33", "baixa": "36"}
    print("Bateria de dependências — resultados")
    print(f"Pacotes inventariados: {stats['pacotes']} | Achados: {stats['total']}"
          f" (alta: {stats['por_severidade']['alta']}, média: {stats['por_severidade']['media']},"
          f" baixa: {stats['por_severidade']['baixa']})")
    if stats.get("modo"):
        print(f"Modo: {stats['modo']}")
    print("Lembrete: cada item é um candidato; confirme aplicabilidade no artefato implantado.")
    print()
    atual = None
    for a in achados:
        if a["severidade"] != atual:
            atual = a["severidade"]
            print(cor(f"== Severidade {atual.upper()} ==", mapa_cor[atual], ativo_cor))
        print(f"[{a['categoria']}/{a['id']}] {a['titulo']} (confiança: {a['confianca']})")
        print(f"  local: {a['arquivo']}:{a['linha'] or '—'}  {a['trecho']}")
        print(f"  ação: {a['acao']}")
        print()


def principal(argv=None):
    parser = argparse.ArgumentParser(
        description="Verificação de dependências (SCA) contra o OSV; somente leitura.")
    parser.add_argument("alvos", nargs="+", help="diretório ou lockfile/SBOM a inventariar")
    parser.add_argument("--osv", action="store_true",
                        help="consulta o OSV (envia nome/ecossistema/versão à API pública)")
    parser.add_argument("--cache", help="arquivo de cache JSON (recomendado em CI)")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--espera-osv", type=float, default=0.2, help="pausa entre lotes (padrão: 0.2)")
    parser.add_argument("--falhar-em", choices=["alta", "media", "baixa", "qualquer", "nunca"],
                        default="alta", help="código de saída 1 a partir desta severidade")
    parser.add_argument("--json", help="grava relatório JSON")
    parser.add_argument("--resumo", action="store_true", help="imprime apenas o resumo")
    parser.add_argument("--sem-cor", action="store_true")
    args = parser.parse_args(argv)

    inventario = inventariar(args.alvos)
    por_eco = {}
    for p in inventario:
        por_eco[p["ecossistema"]] = por_eco.get(p["ecossistema"], 0) + 1

    achados = []
    modo = "inventário (sem consulta ao OSV)" if not args.osv else "consulta ao OSV"
    if args.osv and inventario:
        try:
            vulnerabilidades = consultar_osv(inventario, cache=args.cache, timeout=args.timeout,
                                             espera=args.espera_osv)
            achados = construir_achados(inventario, vulnerabilidades)
        except RuntimeError as e:
            print(f"erro de conexão: {e}\nbateria de dependências interrompida.", file=sys.stderr)
            sys.exit(2)
    elif not inventario:
        print("nenhum lockfile/SBOM reconhecido; nada a inventariar.", file=sys.stderr)

    achados = ordenar(achados)
    por_severidade = {"alta": 0, "media": 0, "baixa": 0}
    for a in achados:
        por_severidade[a["severidade"]] += 1
    stats = dict(pacotes=len(inventario), total=len(achados), por_severidade=por_severidade,
                 por_ecossistema=por_eco, modo=modo)

    ativo_cor = sys.stdout.isatty() and not args.sem_cor
    if args.resumo:
        print(f"pacotes: {stats['pacotes']} | achados: {stats['total']}"
              f" | alta: {por_severidade['alta']} | média: {por_severidade['media']}"
              f" | baixa: {por_severidade['baixa']}")
    else:
        imprimir(achados, stats, ativo_cor)

    if args.json:
        relatorio = dict(
            ferramenta="verificacao_dependencias", versao="1.1",
            gerado_em=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            alvos=args.alvos, modo=modo, resumo=stats, inventario=inventario,
            achados=achados,
        )
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, ensure_ascii=False, indent=2)
        print(f"relatório JSON gravado em: {args.json}")

    if args.falhar_em != "nunca" and args.osv:
        limite = {"alta": 2, "media": 1, "baixa": 0, "qualquer": 0}[args.falhar_em]
        if any(SEVERIDADES[a["severidade"]] >= limite for a in achados):
            sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    principal()
