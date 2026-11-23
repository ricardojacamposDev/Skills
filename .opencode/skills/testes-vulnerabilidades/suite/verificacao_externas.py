#!/usr/bin/env python3
"""Camada opcional: ferramentas externas de segurança (gitleaks, semgrep, trivy), quando instaladas.

A bateria nativa continua sendo a base e não depende de nada disto. Cada ferramenta só roda se
estiver instalada e se a camada for pedida (--externas no orquestrador). Regras de segurança:

  - Nada de rede por padrão: trivy roda com --skip-db-update (usa a base já baixada) e semgrep exige
    uma configuração explícita (--semgrep-config); "auto" baixaria regras e enviaria métricas.
    Com --externas-rede, trivy pode atualizar a base e semgrep pode baixar regras de um registro.
    Nenhuma das duas envia o código do projeto.
  - Valores de segredo NUNCA são copiados do resultado das ferramentas: só regra, arquivo e linha.
  - As ferramentas rodam com diretório de trabalho neutro (temporário), para não herdarem
    configuração local do cwd; o alvo é passado como argumento.
  - Saída é dado do alvo/da ferramenta: caracteres de controle são neutralizados.

Achados saem no mesmo formato da bateria estática (categoria, id, titulo, severidade, confianca,
cwe, arquivo, linha, trecho, acao) e continuam sendo candidatos a achado.
"""

import json
import os
import re
import shutil
import subprocess
import tempfile

FERRAMENTAS = ("gitleaks", "semgrep", "trivy")
LIMITE_SAIDA = 50_000_000
_CONTROLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

SEVERIDADE = {"CRITICAL": "alta", "HIGH": "alta", "ERROR": "alta",
              "MEDIUM": "media", "WARNING": "media",
              "LOW": "baixa", "INFO": "baixa", "UNKNOWN": "baixa"}


def limpar(texto, limite=200):
    return _CONTROLE.sub("?", str(texto or ""))[:limite]


def severidade(valor):
    return SEVERIDADE.get(str(valor or "").upper(), "baixa")


def instalada(nome):
    return shutil.which(nome) is not None


def _rodar(comando, timeout, env_extra=None):
    """Executa sem shell, com cwd neutro e saída limitada. Retorna (código, stdout, stderr)."""
    env = dict(os.environ)
    env.update(env_extra or {})
    with tempfile.TemporaryDirectory() as neutro:
        p = subprocess.run(comando, capture_output=True, cwd=neutro, env=env, timeout=timeout)
    return p.returncode, p.stdout[:LIMITE_SAIDA].decode("utf-8", errors="replace"), \
        p.stderr[:20_000].decode("utf-8", errors="replace")


def _achado(categoria, id_, titulo, sev, confianca, cwe, arquivo, linha, trecho, acao):
    return dict(categoria=categoria, id=limpar(id_, 80), titulo=limpar(titulo, 160), severidade=sev,
                confianca=confianca, cwe=limpar(cwe, 40), arquivo=limpar(arquivo, 300),
                linha=int(linha or 0), trecho=limpar(trecho), acao=limpar(acao, 300))


# ---------- gitleaks ----------

def comando_gitleaks(alvo, relatorio, historico):
    cmd = ["gitleaks", "detect", "--source", alvo, "--report-format", "json", "--report-path", relatorio,
           "--redact", "--no-banner", "--exit-code", "0"]
    if not historico:
        cmd.append("--no-git")
    return cmd


def parse_gitleaks(dados):
    achados = []
    for r in dados if isinstance(dados, list) else []:
        if not isinstance(r, dict):
            continue
        # Secret/Match são propositalmente ignorados: nunca copiar valor de segredo.
        commit = r.get("Commit") or ""
        arquivo = f"git:{commit[:12]}:{r.get('File', '')}" if commit else r.get("File", "")
        achados.append(_achado(
            "SEGREDO", f"gitleaks:{r.get('RuleID', '')}", f"Possível segredo ({r.get('Description') or r.get('RuleID', '')})",
            "alta", "media", "CWE-798", arquivo, r.get("StartLine"), "(valor não exibido)",
            "Trate como credencial exposta: rotacione pelo fluxo autorizado (gestao-segredos); nunca copie o valor."))
    return achados


# ---------- semgrep ----------

def comando_semgrep(alvo, config):
    return ["semgrep", "scan", "--config", config, "--json", "--metrics=off", "--disable-version-check",
            "--quiet", "--timeout", "30", alvo]


def _cwe_semgrep(meta):
    cwe = (meta or {}).get("cwe") or ""
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else ""
    m = re.search(r"CWE-\d+", str(cwe))
    return m.group(0) if m else ""


def parse_semgrep(dados):
    achados = []
    resultados = dados.get("results") if isinstance(dados, dict) else None
    for r in resultados or []:
        if not isinstance(r, dict):
            continue
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        confianca = {"high": "alta", "medium": "media", "low": "baixa"}.get(str(meta.get("confidence", "")).lower(), "media")
        achados.append(_achado(
            "SAST", f"semgrep:{r.get('check_id', '')}", extra.get("message") or r.get("check_id", ""),
            severidade(extra.get("severity")), confianca,
            _cwe_semgrep(meta), r.get("path", ""), (r.get("start") or {}).get("line"),
            r.get("check_id", ""),  # não copia extra.lines: a linha pode conter segredo
            "Confirme a alcançabilidade lendo o fluxo de dados; corrija pela causa raiz (seguranca-aplicacoes)."))
    return achados


# ---------- trivy ----------

def comando_trivy(alvo, rede):
    cmd = ["trivy", "fs", "--format", "json", "--quiet", "--scanners", "vuln,secret,misconfig"]
    if not rede:
        cmd += ["--skip-db-update", "--skip-java-db-update"]
    return cmd + [alvo]


def parse_trivy(dados):
    achados = []
    for res in (dados.get("Results") if isinstance(dados, dict) else None) or []:
        if not isinstance(res, dict):
            continue
        alvo = res.get("Target", "")
        for v in res.get("Vulnerabilities") or []:
            corrigida = v.get("FixedVersion")
            achados.append(_achado(
                "DEPENDENCIA", f"trivy:{v.get('VulnerabilityID', '')}",
                f"{v.get('PkgName', '')} {v.get('InstalledVersion', '')}: {v.get('Title') or v.get('VulnerabilityID', '')}",
                severidade(v.get("Severity")), "media", "", alvo, 0, v.get("VulnerabilityID", ""),
                f"Atualize para {corrigida}; confirme versão no artefato final e alcançabilidade (resposta-vulnerabilidades)."
                if corrigida else "Sem correção publicada: avalie mitigação e alcançabilidade (pesquisa-vulnerabilidades)."))
        for s in res.get("Secrets") or []:
            achados.append(_achado(
                "SEGREDO", f"trivy:{s.get('RuleID', '')}", f"Possível segredo ({s.get('Title') or s.get('RuleID', '')})",
                "alta", "media", "CWE-798", alvo, s.get("StartLine"), "(valor não exibido)",
                "Trate como credencial exposta: rotacione pelo fluxo autorizado (gestao-segredos); nunca copie o valor."))
        for m in res.get("Misconfigurations") or []:
            achados.append(_achado(
                "IAC", f"trivy:{m.get('ID', '')}", m.get("Title") or m.get("Message", ""), severidade(m.get("Severity")),
                "media", "", alvo, (m.get("CauseMetadata") or {}).get("StartLine"), m.get("Message", ""),
                m.get("Resolution") or "Corrija no IaC/manifest (seguranca-infraestrutura)."))
    return achados


# ---------- execução ----------

def executar(nome, alvo, *, rede=False, semgrep_config=None, historico=False, timeout=600):
    """Roda uma ferramenta. Retorna (situacao, detalhe, achados).

    situacao: "executada", "não instalada", "não executada" ou "erro".
    """
    if not instalada(nome):
        return "não instalada", f"{nome} não encontrado no PATH (opcional)", []
    alvo = os.path.abspath(alvo)
    try:
        if nome == "gitleaks":
            with tempfile.TemporaryDirectory() as tmp:
                relatorio = os.path.join(tmp, "gitleaks.json")
                codigo, _, erro = _rodar(comando_gitleaks(alvo, relatorio, historico), timeout)
                if codigo != 0:
                    return "erro", limpar(erro.strip().splitlines()[-1] if erro.strip() else f"código {codigo}"), []
                dados = []
                if os.path.exists(relatorio) and os.path.getsize(relatorio) <= LIMITE_SAIDA:
                    with open(relatorio, "r", encoding="utf-8") as f:
                        dados = json.load(f) or []
                achados = parse_gitleaks(dados)
        elif nome == "semgrep":
            if not semgrep_config:
                return "não executada", ("semgrep exige --semgrep-config explícito (ex.: pasta de regras local); "
                                         "'auto' baixaria regras da internet"), []
            env = {"SEMGREP_SEND_METRICS": "off"}
            codigo, saida, erro = _rodar(comando_semgrep(alvo, semgrep_config), timeout, env)
            if codigo not in (0, 1):
                return "erro", limpar(erro.strip().splitlines()[-1] if erro.strip() else f"código {codigo}"), []
            achados = parse_semgrep(json.loads(saida or "{}"))
        elif nome == "trivy":
            codigo, saida, erro = _rodar(comando_trivy(alvo, rede), timeout)
            if codigo != 0:
                dica = "" if rede else " (sem base de vulnerabilidades local? use --externas-rede para atualizá-la)"
                return "erro", limpar((erro.strip().splitlines() or [f"código {codigo}"])[-1]) + dica, []
            achados = parse_trivy(json.loads(saida or "{}"))
        else:
            return "não executada", f"ferramenta desconhecida: {nome}", []
    except subprocess.TimeoutExpired:
        return "erro", f"{nome} excedeu {timeout}s", []
    except (OSError, ValueError) as e:
        return "erro", limpar(f"{nome}: {e}"), []
    return "executada", f"{len(achados)} achado(s)", achados
