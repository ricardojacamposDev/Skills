"""Testes do orquestrador da varredura (varredura.py).

Uso: python3 test_varredura.py

Usa um projeto fictício em pasta temporária e, para a camada HTTP, um servidor
sintético em 127.0.0.1. Nenhum teste acessa a rede externa (sem --osv).
"""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

import importlib.util

PASTA = Path(__file__).resolve().parent


def carregar(nome):
    spec = importlib.util.spec_from_file_location(nome, PASTA / f"{nome}.py")
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo


varredura = carregar("varredura")
teste_http = carregar("test_verificacao_http")


def projeto(pasta):
    (pasta / "app.py").write_text('app.run(debug=True)\nreturn redirect(request.args.get("next"))\n', encoding="utf-8")
    (pasta / "package-lock.json").write_text(json.dumps(
        {"packages": {"node_modules/lodash": {"version": "4.17.20"}}}), encoding="utf-8")


class TesteVarredura(unittest.TestCase):
    def executar(self, argv):
        saida = io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(io.StringIO()):
            codigo = varredura.principal(argv)
        return codigo, saida.getvalue()

    def test_estatica_e_inventario(self):
        with tempfile.TemporaryDirectory() as tmp:
            alvo = Path(tmp) / "projeto"
            alvo.mkdir()
            projeto(alvo)
            relatorios = alvo / "relatorio-seguranca"
            codigo, _ = self.executar([str(alvo), "--saida", str(relatorios), "--falhar-em", "media"])
            self.assertEqual(codigo, 1, "achado médio deve quebrar com --falhar-em media")
            dados = json.loads((relatorios / "varredura.json").read_text(encoding="utf-8"))
            ids = {a["id"] for a in dados["achados"]}
            self.assertTrue({"flask-debug-run", "redirect-aberto-py"} <= ids)
            self.assertEqual(dados["camadas"]["dependências"]["situacao"], "só inventário")
            self.assertEqual(dados["camadas"]["HTTP"]["situacao"], "não executada")
            self.assertTrue(all(a["estado"] == "hipótese" for a in dados["achados"]))
            md = (relatorios / "varredura.md").read_text(encoding="utf-8")
            self.assertIn("Cobertura OWASP Top 10", md)
            self.assertIn("Não coberto pela varredura automática", md)
            self.assertEqual((relatorios / ".gitignore").read_text(encoding="utf-8"), "*\n")
            # Segunda execução não deve varrer os próprios relatórios.
            self.executar([str(alvo), "--saida", str(relatorios), "--falhar-em", "nunca"])
            dados2 = json.loads((relatorios / "varredura.json").read_text(encoding="utf-8"))
            self.assertFalse(any("relatorio-seguranca" in a["local"] for a in dados2["achados"]))

    def test_http_exige_autorizacao(self):
        with tempfile.TemporaryDirectory() as tmp:
            alvo = Path(tmp)
            projeto(alvo)
            _, saida = self.executar([str(alvo), "--saida", str(alvo / "r"), "--url", "http://127.0.0.1:9",
                                      "--falhar-em", "nunca"])
            self.assertIn("sem --autorizado", saida)

    def test_http_autorizado_em_servidor_local(self):
        with tempfile.TemporaryDirectory() as tmp, teste_http.servidor(teste_http.Vulneravel) as url:
            alvo = Path(tmp)
            projeto(alvo)
            codigo, _ = self.executar([str(alvo), "--saida", str(alvo / "r"), "--url", url, "--autorizado",
                                       "--espera-http", "0", "--falhar-em", "nunca"])
            self.assertEqual(codigo, 0)
            dados = json.loads((alvo / "r" / "varredura.json").read_text(encoding="utf-8"))
            self.assertEqual(dados["camadas"]["HTTP"]["situacao"], "executada")
            self.assertTrue(any(a["camada"] == "HTTP" and a["titulo"] == "Redirecionamento aberto"
                                for a in dados["achados"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
