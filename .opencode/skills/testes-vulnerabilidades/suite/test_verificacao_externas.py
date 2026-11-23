"""Testes da camada de ferramentas externas (verificacao_externas.py).

Nenhuma ferramenta real é necessária: executáveis falsos no PATH registram os argumentos recebidos
e devolvem JSON no formato documentado de cada ferramenta. Sem rede.
"""

import contextlib
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PASTA = Path(__file__).resolve().parent


def carregar(nome):
    spec = importlib.util.spec_from_file_location(nome, PASTA / f"{nome}.py")
    modulo = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(nome, modulo)
    spec.loader.exec_module(modulo)
    return modulo


ve = carregar("verificacao_externas")
varredura = carregar("varredura")

SEGREDO = "Zx9" + "qWv7Lm2Pk4"  # sintético; as ferramentas reais devolveriam o valor em Secret/Match

FALSO = f"""#!{sys.executable}
import json, os, sys
nome = os.path.basename(sys.argv[0])
with open(os.environ["FAKE_LOG"], "a") as f:
    f.write(json.dumps({{"tool": nome, "args": sys.argv[1:], "cwd": os.getcwd()}}) + "\\n")
saida = json.load(open(os.environ["FAKE_DADOS"]))[nome]
if saida.get("codigo", 0) != 0:
    sys.stderr.write(saida.get("erro", "falhou"))
    sys.exit(saida["codigo"])
if nome == "gitleaks":
    json.dump(saida["json"], open(sys.argv[sys.argv.index("--report-path") + 1], "w"))
else:
    print(json.dumps(saida["json"]))
"""

DADOS = {
    "gitleaks": {"json": [{"RuleID": "generic-api-key", "Description": "Generic API Key", "File": "app/config.py",
                           "StartLine": 7, "Secret": SEGREDO, "Match": f'key = "{SEGREDO}"', "Commit": ""}]},
    "semgrep": {"json": {"results": [{
        "check_id": "python.sqli", "path": "app/db.py", "start": {"line": 12},
        "extra": {"severity": "ERROR", "message": "SQL montado com entrada", "lines": f'x = "{SEGREDO}"',
                  "metadata": {"cwe": ["CWE-89: SQL Injection"], "confidence": "HIGH"}}}]}},
    "trivy": {"json": {"Results": [
        {"Target": "package-lock.json", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2021-23337", "PkgName": "lodash", "InstalledVersion": "4.17.20",
             "FixedVersion": "4.17.21", "Severity": "HIGH", "Title": "Command injection"}]},
        {"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS002", "Title": "Imagem roda como root", "Message": "USER ausente", "Severity": "HIGH",
             "Resolution": "Adicione USER", "CauseMetadata": {"StartLine": 1}}]},
        {"Target": "app/config.py", "Secrets": [
            {"RuleID": "aws-key", "Title": "AWS key", "Severity": "CRITICAL", "StartLine": 3, "Match": SEGREDO}]},
    ]}},
}


class Ambiente(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        raiz = Path(self.tmp.name)
        self.bin = raiz / "bin"
        self.bin.mkdir()
        self.alvo = raiz / "projeto"
        self.alvo.mkdir()
        (self.alvo / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.log = raiz / "log.jsonl"
        self.dados = raiz / "dados.json"
        self.dados.write_text(json.dumps(DADOS), encoding="utf-8")
        for nome in ve.FERRAMENTAS:
            exe = self.bin / nome
            exe.write_text(FALSO, encoding="utf-8")
            exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
        env = {"PATH": str(self.bin) + os.pathsep + os.environ["PATH"], "FAKE_LOG": str(self.log),
               "FAKE_DADOS": str(self.dados)}
        self.patcher = mock.patch.dict(os.environ, env)
        self.patcher.start()

    def tearDown(self):
        self.patcher.stop()
        self.tmp.cleanup()

    def chamadas(self):
        return [json.loads(l) for l in self.log.read_text(encoding="utf-8").splitlines()] if self.log.exists() else []

    def ajustar(self, nome, **kw):
        d = json.loads(self.dados.read_text(encoding="utf-8"))
        d[nome].update(kw)
        self.dados.write_text(json.dumps(d), encoding="utf-8")


class TesteExecucao(Ambiente):
    def test_gitleaks_redige_e_nunca_copia_o_valor(self):
        situacao, _, achados = ve.executar("gitleaks", str(self.alvo))
        self.assertEqual(situacao, "executada")
        self.assertEqual(achados[0]["categoria"], "SEGREDO")
        self.assertEqual((achados[0]["arquivo"], achados[0]["linha"]), ("app/config.py", 7))
        self.assertNotIn(SEGREDO, json.dumps(achados))
        args = self.chamadas()[0]["args"]
        self.assertIn("--redact", args)
        self.assertIn("--no-git", args, "sem --historico só a árvore de trabalho")
        _, _, com_hist = ve.executar("gitleaks", str(self.alvo), historico=True)
        self.assertNotIn("--no-git", self.chamadas()[-1]["args"])

    def test_semgrep_exige_config_e_desliga_metricas(self):
        situacao, detalhe, achados = ve.executar("semgrep", str(self.alvo))
        self.assertEqual((situacao, achados), ("não executada", []))
        self.assertEqual(self.chamadas(), [], "sem config explícita nem chega a executar")
        situacao, _, achados = ve.executar("semgrep", str(self.alvo), semgrep_config="regras/")
        self.assertEqual(situacao, "executada")
        a = achados[0]
        self.assertEqual((a["categoria"], a["severidade"], a["cwe"], a["confianca"]), ("SAST", "alta", "CWE-89", "alta"))
        self.assertNotIn(SEGREDO, json.dumps(achados), "extra.lines pode conter segredo e não é copiado")
        self.assertIn("--metrics=off", self.chamadas()[0]["args"])

    def test_trivy_sem_rede_pula_atualizacao_de_base(self):
        situacao, _, achados = ve.executar("trivy", str(self.alvo))
        self.assertEqual(situacao, "executada")
        self.assertIn("--skip-db-update", self.chamadas()[0]["args"])
        ve.executar("trivy", str(self.alvo), rede=True)
        self.assertNotIn("--skip-db-update", self.chamadas()[1]["args"])
        por_cat = {a["categoria"]: a for a in achados}
        self.assertEqual(set(por_cat), {"DEPENDENCIA", "IAC", "SEGREDO"})
        self.assertIn("4.17.21", por_cat["DEPENDENCIA"]["acao"])
        self.assertNotIn(SEGREDO, json.dumps(achados))

    def test_trivy_sem_base_orienta_o_usuario(self):
        self.ajustar("trivy", codigo=1, erro="DB error\nbase de vulnerabilidades ausente")
        situacao, detalhe, _ = ve.executar("trivy", str(self.alvo))
        self.assertEqual(situacao, "erro")
        self.assertIn("--externas-rede", detalhe)

    def test_cwd_neutro_e_alvo_absoluto(self):
        ve.executar("trivy", str(self.alvo))
        chamada = self.chamadas()[0]
        self.assertNotEqual(os.path.realpath(chamada["cwd"]), os.path.realpath(self.alvo))
        self.assertEqual(chamada["args"][-1], os.path.abspath(self.alvo))

    def test_ferramenta_ausente_nao_e_erro(self):
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent"}):
            situacao, _, achados = ve.executar("gitleaks", str(self.alvo))
        self.assertEqual((situacao, achados), ("não instalada", []))

    def test_saida_com_caracteres_de_controle_e_neutralizada(self):
        self.ajustar("semgrep", json={"results": [{"check_id": "r\x1b[31m", "path": "a.py", "start": {"line": 1},
                                                    "extra": {"severity": "INFO", "message": "m\x07"}}]})
        _, _, achados = ve.executar("semgrep", str(self.alvo), semgrep_config="x")
        self.assertNotIn("\x1b", json.dumps(achados, ensure_ascii=False))
        self.assertNotIn("\x07", json.dumps(achados, ensure_ascii=False))

    def test_json_invalido_vira_erro_sem_derrubar(self):
        exe = self.bin / "trivy"
        exe.write_text(f"#!{sys.executable}\nprint('não é json')\n", encoding="utf-8")
        situacao, detalhe, _ = ve.executar("trivy", str(self.alvo))
        self.assertEqual(situacao, "erro")


class TesteOrquestrador(Ambiente):
    def rodar(self, *extra):
        saida = self.alvo.parent / "rel"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            codigo = varredura.principal([str(self.alvo), "--saida", str(saida), "--falhar-em", "nunca", *extra])
        return codigo, json.loads((saida / "varredura.json").read_text(encoding="utf-8")), \
            (saida / "varredura.md").read_text(encoding="utf-8")

    def test_sem_flag_nenhuma_ferramenta_externa_roda(self):
        _, rel, _ = self.rodar()
        self.assertEqual(self.chamadas(), [])
        self.assertEqual(rel["camadas"]["externas"]["situacao"], "não executada")

    def test_com_flag_consolida_achados_e_nunca_vaza_segredo(self):
        codigo, rel, md = self.rodar("--externas", "--semgrep-config", "regras/")
        self.assertEqual(codigo, 0)
        for nome in ve.FERRAMENTAS:
            self.assertEqual(rel["camadas"][f"externa: {nome}"]["situacao"], "executada")
        camadas = {a["camada"] for a in rel["achados"]}
        self.assertEqual(camadas, {"externa: gitleaks", "externa: semgrep", "externa: trivy"})
        self.assertNotIn(SEGREDO, json.dumps(rel) + md)

    def test_ferramenta_ausente_aparece_no_relatorio(self):
        with mock.patch.dict(os.environ, {"PATH": os.path.dirname(sys.executable)}):
            codigo, rel, _ = self.rodar("--externas")
        self.assertEqual(rel["camadas"]["externa: semgrep"]["situacao"], "não instalada")
        self.assertEqual(codigo, 0, "ferramenta opcional ausente não falha a varredura")

    def test_erro_de_ferramenta_vira_codigo_2(self):
        self.ajustar("trivy", codigo=1, erro="boom")
        codigo, rel, _ = self.rodar("--externas")
        self.assertEqual(codigo, 2)
        self.assertEqual(rel["camadas"]["externa: trivy"]["situacao"], "erro")


if __name__ == "__main__":
    unittest.main(verbosity=2)
