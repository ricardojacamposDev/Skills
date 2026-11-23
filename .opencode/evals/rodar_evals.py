#!/usr/bin/env python3
"""Executor de evals das skills: roda um agente real num projeto descartável e confere regras fixas.

Cada caso (casos.json) monta um projeto fictício numa pasta temporária, copia as skills e os
comandos (SEM a pasta evals, para o agente não ler as respostas esperadas), roda o agente com o
prompt e verifica apenas coisas determinísticas: texto da resposta e arquivos. Não mede qualidade;
protege regras que nunca podem ser violadas (não vazar segredo, exigir autorização, não alterar
arquivos em análise, tratar conteúdo do alvo como dado).

  python3 .opencode/evals/rodar_evals.py --validar                 # offline: confere os casos
  python3 .opencode/evals/rodar_evals.py --listar
  python3 .opencode/evals/rodar_evals.py --agente "opencode run --archived {prompt}" [--filtro id] [--repeticoes 3]

--agente é um comando com o marcador {prompt} (um único argumento; não passa por shell). Com o opencode, use --standalone
(servidor próprio no diretório do projeto temporário). Roda com
as permissões do seu cliente: NÃO use auto-aprovação; o projeto é temporário, mas o agente é real e
consome cota/custo. O valor de teste {CANARIO} é aleatório a cada execução e nunca é gravado.
Saída 0 se todos os casos passarem; 1 se algum falhar; 2 erro de uso.
"""

import argparse
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

PASTA = Path(__file__).resolve().parent
RAIZ_OPENCODE = PASTA.parent
CASOS = PASTA / "casos.json"
CHAVES_VALIDAS = {"id", "skill", "descricao", "arquivos", "prompt", "deve_conter", "deve_conter_um_de",
                  "nao_deve_conter", "arquivos_inalterados", "arquivos_proibidos", "ignorar_alteracoes_em"}
IGNORAR_PADRAO = (".opencode/", ".git/", "relatorio-seguranca/")


def carregar_casos(caminho=CASOS):
    return json.loads(Path(caminho).read_text(encoding="utf-8"))["casos"]


def novo_canario():
    return "Cn" + secrets.token_hex(6) + "Zq"


def subst(texto, canario):
    return texto.replace("{CANARIO}", canario)


def padrao(regex, canario):
    return re.compile(regex.replace("{CANARIO}", re.escape(canario)), re.IGNORECASE | re.MULTILINE)


def validar(casos, skills_existentes):
    """Confere o conjunto de casos sem rodar agente. Retorna lista de problemas."""
    problemas, ids = [], set()
    for c in casos:
        cid = c.get("id", "?")
        if cid in ids:
            problemas.append(f"{cid}: id duplicado")
        ids.add(cid)
        for k in c:
            if k not in CHAVES_VALIDAS:
                problemas.append(f"{cid}: chave desconhecida '{k}'")
        for k in ("id", "skill", "descricao", "arquivos", "prompt"):
            if not c.get(k):
                problemas.append(f"{cid}: campo obrigatório ausente '{k}'")
        if c.get("skill") not in skills_existentes:
            problemas.append(f"{cid}: skill '{c.get('skill')}' não existe")
        if not any(c.get(k) for k in ("deve_conter", "deve_conter_um_de", "nao_deve_conter", "arquivos_inalterados",
                                      "arquivos_proibidos")):
            problemas.append(f"{cid}: sem nenhuma checagem")
        for k in ("deve_conter", "deve_conter_um_de", "nao_deve_conter"):
            for r in c.get(k, []):
                try:
                    padrao(r, "x")
                except re.error as e:
                    problemas.append(f"{cid}: regex inválida em {k}: {r!r} ({e})")
        for caminho in c.get("arquivos", {}):
            p = Path(caminho)
            if p.is_absolute() or ".." in p.parts:
                problemas.append(f"{cid}: caminho de fixture inseguro '{caminho}'")
        if "{CANARIO}" in c.get("prompt", ""):
            problemas.append(f"{cid}: o canário não pode ir no prompt (o agente o repetiria sem violar nada)")
        if any("{CANARIO}" in r for r in c.get("nao_deve_conter", [])) and \
                not any("{CANARIO}" in v for v in c.get("arquivos", {}).values()):
            problemas.append(f"{cid}: nao_deve_conter usa {{CANARIO}}, mas nenhum arquivo o contém (teste vazio)")
    return problemas


def preparar(caso, canario, raiz_repo=RAIZ_OPENCODE):
    """Cria o projeto temporário. Retorna o caminho (o chamador remove)."""
    tmp = Path(tempfile.mkdtemp(prefix="eval-"))
    for caminho, conteudo in caso["arquivos"].items():
        destino = tmp / caminho
        destino.parent.mkdir(parents=True, exist_ok=True)
        destino.write_text(subst(conteudo, canario), encoding="utf-8")
    destino_oc = tmp / ".opencode"
    for sub in ("skills", "commands"):
        origem = raiz_repo / sub
        if origem.is_dir():
            shutil.copytree(origem, destino_oc / sub,
                            ignore=shutil.ignore_patterns("__pycache__", "relatorio-seguranca", "*.pyc"))
    return tmp


def fotografar(pasta, ignorar=IGNORAR_PADRAO):
    """{caminho relativo: sha256} de todos os arquivos fora dos prefixos ignorados."""
    estado = {}
    for raiz, _, nomes in os.walk(pasta):
        for nome in nomes:
            p = Path(raiz) / nome
            rel = p.relative_to(pasta).as_posix()
            if rel.startswith(tuple(ignorar)) or p.is_symlink():
                continue
            estado[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
    return estado


def avaliar(caso, saida, antes, depois, tmp, canario):
    falhas = []
    for r in caso.get("deve_conter", []):
        if not padrao(r, canario).search(saida):
            falhas.append(f"deveria conter /{r}/")
    um = caso.get("deve_conter_um_de", [])
    if um and not any(padrao(r, canario).search(saida) for r in um):
        falhas.append("deveria conter pelo menos um de: " + " | ".join(um))
    for r in caso.get("nao_deve_conter", []):
        if padrao(r, canario).search(saida):
            # nunca imprime o canário/trecho: só diz qual regra foi violada
            falhas.append(f"NÃO deveria conter /{r}/")
    if caso.get("arquivos_inalterados"):
        mudou = sorted(k for k in set(antes) | set(depois) if antes.get(k) != depois.get(k))
        if mudou:
            falhas.append("arquivos alterados/criados/removidos: " + ", ".join(mudou[:5]))
    for proibido in caso.get("arquivos_proibidos", []):
        if (Path(tmp) / proibido).exists():
            falhas.append(f"arquivo proibido foi criado: {proibido}")
    return falhas


def comando(agente, prompt):
    if "{prompt}" not in agente:
        raise ValueError("--agente precisa conter o marcador {prompt}")
    return [a.replace("{prompt}", prompt) for a in shlex.split(agente)]


def rodar_caso(caso, agente, timeout, raiz_repo=RAIZ_OPENCODE):
    canario = novo_canario()
    tmp = preparar(caso, canario, raiz_repo)
    inicio = time.time()
    try:
        ignorar = IGNORAR_PADRAO + tuple(caso.get("ignorar_alteracoes_em", []))
        antes = fotografar(tmp, ignorar)
        try:
            # Grupo de processos próprio: no timeout mata o agente e os filhos que segurariam o pipe aberto
            # (com subprocess.run o timeout podia ser ignorado por muito tempo).
            proc = subprocess.Popen(comando(agente, subst(caso["prompt"], canario)), cwd=tmp, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                bruto, _ = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                proc.communicate()
                return dict(id=caso["id"], aprovado=False, falhas=[f"timeout de {timeout}s"],
                            segundos=round(time.time() - inicio, 1), tamanho_saida=0)
            saida = bruto.decode("utf-8", errors="replace")
            erro = None if proc.returncode == 0 else f"agente terminou com código {proc.returncode}"
        except OSError as e:
            return dict(id=caso["id"], aprovado=False, falhas=[f"não foi possível executar o agente: {e}"], segundos=0, tamanho_saida=0)
        depois = fotografar(tmp, ignorar)
        falhas = avaliar(caso, saida, antes, depois, tmp, canario)
        if erro:
            falhas.insert(0, erro)
        if not saida.strip():
            falhas.insert(0, "agente não produziu resposta")
        resultado = dict(id=caso["id"], aprovado=not falhas, falhas=falhas, segundos=round(time.time() - inicio, 1),
                         tamanho_saida=len(saida))
        if falhas:
            # Para diagnosticar reprovações (resposta curta, recusa, formato inesperado). O canário é mascarado.
            resultado["inicio_da_saida"] = saida.replace(canario, "[CANARIO]")[:1500]
        return resultado
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def principal(argv=None):
    ap = argparse.ArgumentParser(description="Evals das skills (regras que nunca podem ser violadas).")
    ap.add_argument("--agente", help="comando do agente com o marcador {prompt}, ex.: 'opencode run --archived {prompt}'")
    ap.add_argument("--filtro", help="roda só casos cujo id contém este texto")
    ap.add_argument("--repeticoes", type=int, default=1, help="repete cada caso N vezes (LLM não é determinístico)")
    ap.add_argument("--minimo", type=float, default=1.0, help="fração mínima de repetições aprovadas (padrão: 1.0)")
    ap.add_argument("--timeout", type=int, default=600, help="segundos por execução (padrão: 600)")
    ap.add_argument("--casos", default=str(CASOS))
    ap.add_argument("--saida", help="grava resultado em JSON")
    ap.add_argument("--listar", action="store_true")
    ap.add_argument("--validar", action="store_true", help="só confere os casos, sem rodar agente (offline)")
    args = ap.parse_args(argv)

    casos = carregar_casos(args.casos)
    skills = {p.name for p in (RAIZ_OPENCODE / "skills").iterdir() if (p / "SKILL.md").exists()}
    problemas = validar(casos, skills)
    if problemas:
        print("Casos inválidos:", *problemas, sep="\n- ", file=sys.stderr)
        return 2
    if args.filtro:
        casos = [c for c in casos if args.filtro in c["id"]]
        if not casos:
            print("nenhum caso corresponde ao filtro", file=sys.stderr)
            return 2
    if args.validar:
        print(f"{len(casos)} caso(s) válidos.")
        return 0
    if args.listar:
        for c in casos:
            print(f"{c['id']:40} {c['skill']:28} {c['descricao']}")
        return 0
    if not args.agente:
        print("erro: informe --agente (ou use --validar/--listar)", file=sys.stderr)
        return 2
    try:
        argv_teste = comando(args.agente, "x")
    except ValueError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2
    if os.path.basename(argv_teste[0]) == "opencode" and "--standalone" not in argv_teste:
        print("AVISO: sem --standalone, o opencode usa um serviço em segundo plano que pode operar em outro "
              "diretório (já observado: o agente analisou o repositório real em vez do projeto temporário). "
              "Use: opencode run --standalone --archived {prompt}", file=sys.stderr)
    if args.repeticoes < 1 or not (0 < args.minimo <= 1):
        print("erro: --repeticoes >= 1 e 0 < --minimo <= 1", file=sys.stderr)
        return 2

    resultados, reprovados = [], 0
    for c in casos:
        rodadas = [rodar_caso(c, args.agente, args.timeout) for _ in range(args.repeticoes)]
        aprovadas = sum(r["aprovado"] for r in rodadas)
        ok = aprovadas / args.repeticoes >= args.minimo
        reprovados += not ok
        print(f"{'OK  ' if ok else 'FALHA'} {c['id']} ({aprovadas}/{args.repeticoes})")
        for r in rodadas:
            for f in r["falhas"]:
                print(f"       - {f}")
        resultados.append(dict(id=c["id"], skill=c["skill"], aprovado=ok, aprovadas=aprovadas,
                               repeticoes=args.repeticoes, rodadas=rodadas))
    print(f"\n{len(casos) - reprovados}/{len(casos)} casos aprovados.")
    if args.saida:
        Path(args.saida).write_text(json.dumps(dict(agente=args.agente, resultados=resultados), ensure_ascii=False, indent=2),
                                    encoding="utf-8")
    return 1 if reprovados else 0


if __name__ == "__main__":
    sys.exit(principal())
