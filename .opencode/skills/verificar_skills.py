#!/usr/bin/env python3
"""Verifica a consistência do conjunto de skills (somente leitura, biblioteca padrão).

Checagens:
  - frontmatter: `name` igual ao diretório, padrão ^[a-z0-9]+(-[a-z0-9]+)*$ (1–64), `description` 1–1024;
  - referências cruzadas: `nome-de-skill` em crases que seja quase igual (mas não igual) a uma skill
    existente — erro de digitação ou skill renomeada;
  - índice: toda skill aparece na tabela de .opencode/skills/README.md e no README raiz;
  - links relativos de arquivos .md existem;
  - contagens declaradas ("N skills", "~N padrões") batem com a realidade;
  - scripts citados (`.opencode/skills/.../x.py`) existem;
  - orçamento de tamanho: SKILL.md acima de ORCAMENTO_BYTES é sinal de que precisa ser enxugado;
  - travas de segurança: regras que não podem sumir de skills críticas (ex.: exigir autorização em
    testes ativos, nunca copiar valor de segredo) continuam presentes no texto;
  - exemplo de entrega: cada skill tem `exemplo-entrega.md` com os mesmos rótulos, na mesma ordem, da
    lista de "Formato de entrega" (muda o formato, o exemplo precisa acompanhar), dentro do limite de
    tamanho, e o SKILL.md aponta para ele;
  - comandos (.opencode/commands/*.md) têm `description` e o texto deles não está copiado nos READMEs
    (fonte única: o arquivo do comando).

Uso: python3 .opencode/skills/verificar_skills.py [raiz-do-repositório]   (padrão: sobe até achar .opencode)
Saída 0 sem problemas; 1 com problemas; 2 erro de uso.
"""

import difflib
import re
import sys
from pathlib import Path

NOME_OK = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CRASES = re.compile(r"`([a-z0-9]+(?:-[a-z0-9]+)+)`")
ORCAMENTO_BYTES = 9000
ORCAMENTO_EXEMPLO = 3500
SECAO_FORMATO = re.compile(r"## Formato de entrega\n(.*?)(?:\n\n[A-Z`]|\Z)", re.S)
ROTULO = re.compile(r"^\d+\.\s+\*\*(.+?)\*\*", re.M)
CAMINHO_SCRIPT = re.compile(r"\.opencode/skills/[\w./-]+?\.py")

# skill -> [(regex, o que a regra garante)]. Se alguém "enxugar" a skill e perder a regra, o teste acusa.
TRAVAS = {
    "testes-vulnerabilidades": [(r"(?i)autoriza", "exigir autorização para HTTP/testes ativos"),
                                (r"(?i)nunca reproduza o valor", "nunca reproduzir valor de segredo")],
    "pesquisa-vulnerabilidades": [(r"(?i)autoriza", "exigir autorização antes de teste ativo")],
    "seguranca-aplicacoes": [(r"(?i)autoriza", "exigir autorização para teste ativo")],
    "autenticacao-identidade": [(r"(?i)autoriza", "exigir autorização para teste ativo"),
                                (r"(?i)PKCE", "OAuth com Authorization Code + PKCE"),
                                (r"(?i)n[ãa]o registre, exiba nem reproduza", "nunca expor senha/token")],
    "seguranca-frontend": [(r"(?i)autoriza", "exigir autorização para teste ativo"),
                           (r"(?i)localStorage", "alertar sobre token em localStorage"),
                           (r"(?i)n[ãa]o exiba nem reproduza", "nunca expor token/segredo")],
    "seguranca-infraestrutura": [(r"(?i)autoriza", "exigir autorização para consultar ambiente em execução")],
    "escalabilidade-resiliente": [(r"(?i)autoriza", "exigir autorização para teste de carga")],
    "testes-e2e": [(r"(?i)autoriza", "não rodar E2E em produção sem autorização"),
                   (r"(?i)sint[ée]tic", "dados sintéticos")],
    "gestao-segredos": [(r"(?i)nunca copie o valor", "nunca copiar valor de segredo"),
                        (r"(?i)n[ãa]o rotacione", "rotação só com confirmação")],
    "resposta-incidentes": [(r"(?i)evid[êe]ncias", "preservar evidências")],
}
LINK = re.compile(r"\]\((?!https?://|#|mailto:)([^)\s#]+)")


def frontmatter(texto):
    m = re.match(r"\A---\n(.*?)\n---\n", texto, re.S)
    if not m:
        return None
    campos = {}
    for linha in m.group(1).splitlines():
        if ":" in linha and not linha.startswith(" "):
            k, v = linha.split(":", 1)
            campos[k.strip()] = v.strip()
    return campos


def achar_raiz(inicio):
    for p in [inicio, *inicio.parents]:
        if (p / ".opencode" / "skills").is_dir():
            return p
    return None


def contar_padroes(raiz):
    arquivo = raiz / ".opencode/skills/testes-vulnerabilidades/suite/verificacao_estatica.py"
    if not arquivo.exists():
        return None
    return len(re.findall(r"^\s+dict\(categoria=|^\s*dict\(\s*id=", arquivo.read_text(encoding="utf-8"), re.M)) or None


def verificar(raiz):
    raiz = Path(raiz)
    pasta = raiz / ".opencode" / "skills"
    comandos = raiz / ".opencode" / "commands"
    problemas = []
    skills = {}
    for d in sorted(p for p in pasta.iterdir() if p.is_dir()):
        arq = d / "SKILL.md"
        if not arq.exists():
            continue
        fm = frontmatter(arq.read_text(encoding="utf-8"))
        if fm is None:
            problemas.append(f"{arq.relative_to(raiz)}: frontmatter ausente")
            continue
        nome, desc = fm.get("name", ""), fm.get("description", "")
        if nome != d.name:
            problemas.append(f"{arq.relative_to(raiz)}: name '{nome}' difere do diretório '{d.name}'")
        if not (1 <= len(nome) <= 64 and NOME_OK.match(nome)):
            problemas.append(f"{arq.relative_to(raiz)}: name '{nome}' fora do padrão")
        if not (1 <= len(desc) <= 1024):
            problemas.append(f"{arq.relative_to(raiz)}: description com {len(desc)} caracteres (esperado 1–1024)")
        skills[d.name] = arq

    # referências cruzadas quase corretas
    for nome, arq in skills.items():
        for ref in sorted(set(CRASES.findall(arq.read_text(encoding="utf-8")))):
            if ref in skills or ref == nome:
                continue
            parecida = difflib.get_close_matches(ref, skills, n=1, cutoff=0.8)
            if parecida:
                problemas.append(f"{arq.relative_to(raiz)}: referência `{ref}` não existe; quis dizer `{parecida[0]}`?")

    # scripts citados, orçamento e travas
    for nome, arq in skills.items():
        texto = arq.read_text(encoding="utf-8")
        for caminho in sorted(set(CAMINHO_SCRIPT.findall(texto))):
            if not (raiz / caminho).exists():
                problemas.append(f"{arq.relative_to(raiz)}: script citado não existe: {caminho}")
        if len(texto.encode("utf-8")) > ORCAMENTO_BYTES:
            problemas.append(f"{arq.relative_to(raiz)}: {len(texto.encode('utf-8'))} bytes (orçamento {ORCAMENTO_BYTES}); enxugue")
        for regex, garantia in TRAVAS.get(nome, []):
            if not re.search(regex, texto):
                problemas.append(f"{arq.relative_to(raiz)}: trava de segurança ausente — {garantia}")

    # exemplo de entrega
    for nome, arq in skills.items():
        texto = arq.read_text(encoding="utf-8")
        m = SECAO_FORMATO.search(texto)
        rotulos = ROTULO.findall(m.group(1)) if m else []
        if not rotulos:
            problemas.append(f"{arq.relative_to(raiz)}: seção 'Formato de entrega' sem lista numerada de rótulos")
            continue
        exemplo = arq.parent / "exemplo-entrega.md"
        if "exemplo-entrega.md" not in texto:
            problemas.append(f"{arq.relative_to(raiz)}: não aponta para exemplo-entrega.md")
        if not exemplo.exists():
            problemas.append(f"{arq.parent.relative_to(raiz)}: exemplo-entrega.md ausente")
            continue
        ex = exemplo.read_text(encoding="utf-8")
        if len(ex.encode("utf-8")) > ORCAMENTO_EXEMPLO:
            problemas.append(f"{exemplo.relative_to(raiz)}: {len(ex.encode('utf-8'))} bytes (limite {ORCAMENTO_EXEMPLO})")
        encontrados = ROTULO.findall(ex)
        if encontrados != rotulos:
            problemas.append(f"{exemplo.relative_to(raiz)}: rótulos {encontrados} diferem do formato da skill {rotulos}")

    # índices
    textos = {}
    for rel in ("README.md", ".opencode/skills/README.md"):
        arq = raiz / rel
        if not arq.exists():
            problemas.append(f"{rel}: ausente")
            continue
        textos[rel] = arq.read_text(encoding="utf-8")
        for nome in skills:
            if f"`{nome}`" not in textos[rel]:
                problemas.append(f"{rel}: skill `{nome}` não aparece")
    # contagem declarada
    for rel, texto in textos.items():
        for m in re.finditer(r"\*{0,2}(\d+)\s+skills\*{0,2}", texto):
            if int(m.group(1)) != len(skills):
                problemas.append(f"{rel}: declara {m.group(1)} skills, existem {len(skills)}")
        for m in re.finditer(r"~\s*(\d+)\s+padr", texto):
            real = contar_padroes(raiz)
            if real and abs(int(m.group(1)) - real) > 5:
                problemas.append(f"{rel}: declara ~{m.group(1)} padrões, existem {real}")

    # links relativos
    arquivos_md = [raiz / "README.md", pasta / "README.md", *pasta.glob("*/SKILL.md"), *pasta.glob("*/suite/README.md")]
    for arq in arquivos_md:
        if not arq.exists():
            continue
        for alvo in LINK.findall(arq.read_text(encoding="utf-8")):
            if not (arq.parent / alvo).exists():
                problemas.append(f"{arq.relative_to(raiz)}: link quebrado '{alvo}'")

    # comandos: fonte única
    if comandos.is_dir():
        for cmd in sorted(comandos.glob("*.md")):
            texto = cmd.read_text(encoding="utf-8")
            fm = frontmatter(texto)
            if not fm or not fm.get("description"):
                problemas.append(f"{cmd.relative_to(raiz)}: frontmatter sem description")
            corpo = re.sub(r"\A---\n.*?\n---\n", "", texto, flags=re.S).strip()
            for linha in (l.strip() for l in corpo.splitlines() if len(l.strip()) > 120):
                for rel, t in textos.items():
                    if linha[:120] in t:
                        problemas.append(f"{rel}: copia texto de {cmd.relative_to(raiz)} (mantenha só no arquivo do comando)")
    return sorted(set(problemas)), len(skills)


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    raiz = Path(argv[0]).resolve() if argv else achar_raiz(Path(__file__).resolve().parent)
    if not raiz or not (raiz / ".opencode" / "skills").is_dir():
        print("erro: não encontrei .opencode/skills", file=sys.stderr)
        return 2
    problemas, total = verificar(raiz)
    for p in problemas:
        print(f"- {p}")
    print(f"{total} skills verificadas; {len(problemas)} problema(s).")
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
