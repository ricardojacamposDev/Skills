"""Testes da verificação de dependências (SCA).

Uso: python3 test_verificacao_dependencias.py

Cobrem parseadores de lockfiles, cálculo de CVSS v3, mapeamento de severidade,
montagem de achados e o fluxo de consulta ao OSV com a rede substituída por
mock. Nenhum teste acessa a internet.
"""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

CAMINHO = Path(__file__).resolve().parent / "verificacao_dependencias.py"
spec = importlib.util.spec_from_file_location("verificacao_dependencias", CAMINHO)
vd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vd)


def escrever(pasta, nome, conteudo):
    caminho = Path(pasta) / nome
    caminho.write_text(conteudo, encoding="utf-8")
    return str(caminho)


class TesteParseadores(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pasta = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def test_package_lock_v3(self):
        escrever(self.pasta, "package-lock.json", json.dumps({
            "packages": {
                "": {"name": "app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.20"},
                "node_modules/@scope/pkg": {"version": "1.2.3"},
            }}))
        pacotes = vd.parse_package_lock(Path(self.pasta) / "package-lock.json")
        self.assertIn(("npm", "lodash", "4.17.20"), pacotes)
        self.assertIn(("npm", "@scope/pkg", "1.2.3"), pacotes)
        self.assertNotIn(("npm", "app", "1.0.0"), pacotes)

    def test_package_lock_v1_dependencies(self):
        escrever(self.pasta, "package-lock.json", json.dumps({
            "dependencies": {
                "a": {"version": "1.0.0", "dependencies": {"b": {"version": "2.0.0"}}},
            }}))
        pacotes = vd.parse_package_lock(Path(self.pasta) / "package-lock.json")
        self.assertIn(("npm", "a", "1.0.0"), pacotes)
        self.assertIn(("npm", "b", "2.0.0"), pacotes)

    def test_yarn_lock(self):
        escrever(self.pasta, "yarn.lock", """
lodash@^4.17.20:
  version "4.17.20"
  resolved "https://example.invalid/lodash"

"@scope/pkg@^1.0.0":
  version "1.2.3"
""")
        pacotes = vd.parse_yarn_lock(Path(self.pasta) / "yarn.lock")
        self.assertIn(("npm", "lodash", "4.17.20"), pacotes)
        self.assertIn(("npm", "@scope/pkg", "1.2.3"), pacotes)

    def test_requirements_somente_pino_exato(self):
        escrever(self.pasta, "requirements.txt", """
django==3.2.0
requests>=2.0
# flask==2.0.1
-r outro.txt
""")
        pacotes = vd.parse_requirements(Path(self.pasta) / "requirements.txt")
        self.assertEqual(pacotes, [("PyPI", "django", "3.2.0")])

    def test_poetry_lock(self):
        escrever(self.pasta, "poetry.lock", """
[[package]]
name = "django"
version = "3.2.0"

[[package]]
name = "requests"
version = "2.25.1"
""")
        pacotes = vd._parse_toml_packages(Path(self.pasta) / "poetry.lock", "PyPI")
        self.assertIn(("PyPI", "django", "3.2.0"), pacotes)
        self.assertIn(("PyPI", "requests", "2.25.1"), pacotes)

    def test_pipfile_lock(self):
        escrever(self.pasta, "Pipfile.lock", json.dumps({
            "default": {"django": {"version": "==3.2.0"}},
            "develop": {"pytest": {"version": "==6.2.0"}},
        }))
        pacotes = vd.parse_pipfile_lock(Path(self.pasta) / "Pipfile.lock")
        self.assertIn(("PyPI", "django", "3.2.0"), pacotes)
        self.assertIn(("PyPI", "pytest", "6.2.0"), pacotes)

    def test_gemfile_lock(self):
        escrever(self.pasta, "Gemfile.lock", """
GEM
  remote: https://rubygems.org/
  specs:
    rails (6.0.0)
    nokogiri (1.11.0)

PLATFORMS
  ruby
""")
        pacotes = vd.parse_gemfile_lock(Path(self.pasta) / "Gemfile.lock")
        self.assertIn(("RubyGems", "rails", "6.0.0"), pacotes)
        self.assertIn(("RubyGems", "nokogiri", "1.11.0"), pacotes)

    def test_go_sum_ignora_go_mod(self):
        escrever(self.pasta, "go.sum", """
github.com/foo/bar v1.2.3 h1:abc=
github.com/foo/bar v1.2.3/go.mod h1:def=
""")
        pacotes = vd.parse_go_sum(Path(self.pasta) / "go.sum")
        self.assertEqual(pacotes, [("Go", "github.com/foo/bar", "1.2.3")])

    def test_composer_lock(self):
        escrever(self.pasta, "composer.lock", json.dumps({
            "packages": [{"name": "monolog/monolog", "version": "2.2.0"}],
            "packages-dev": [{"name": "phpunit/phpunit", "version": "9.5.0"}],
        }))
        pacotes = vd.parse_composer_lock(Path(self.pasta) / "composer.lock")
        self.assertIn(("Packagist", "monolog/monolog", "2.2.0"), pacotes)
        self.assertIn(("Packagist", "phpunit/phpunit", "9.5.0"), pacotes)

    def test_cargo_lock(self):
        escrever(self.pasta, "Cargo.lock", """
[[package]]
name = "openssl"
version = "0.10.0"
""")
        pacotes = vd._parse_toml_packages(Path(self.pasta) / "Cargo.lock", "crates.io")
        self.assertEqual(pacotes, [("crates.io", "openssl", "0.10.0")])

    def test_cyclonedx_purl(self):
        escrever(self.pasta, "sbom.cdx.json", json.dumps({
            "components": [
                {"type": "library", "purl": "pkg:npm/lodash@4.17.20"},
                {"type": "library", "purl": "pkg:pypi/django@3.2.0"},
            ]}))
        pacotes = vd.parse_cyclonedx(Path(self.pasta) / "sbom.cdx.json")
        self.assertIn(("npm", "lodash", "4.17.20"), pacotes)
        self.assertIn(("PyPI", "django", "3.2.0"), pacotes)

    def test_requirements_extras_e_marcadores(self):
        escrever(self.pasta, "requirements.txt", 'uvicorn[standard]==0.20.0\npywin32==306 ; sys_platform == "win32"\n')
        pacotes = vd.parse_requirements(Path(self.pasta) / "requirements.txt")
        self.assertEqual(pacotes, [("PyPI", "uvicorn", "0.20.0"), ("PyPI", "pywin32", "306")])

    def test_pnpm_chaves_com_aspas_e_peer(self):
        escrever(self.pasta, "pnpm-lock.yaml", """lockfileVersion: '9.0'
packages:
  '@babel/core@7.20.0':
    resolution: {integrity: x}
  lodash@4.17.20:
    resolution: {integrity: y}
  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: z}
""")
        pacotes = vd.parse_pnpm_lock(Path(self.pasta) / "pnpm-lock.yaml")
        self.assertIn(("npm", "@babel/core", "7.20.0"), pacotes)
        self.assertIn(("npm", "lodash", "4.17.20"), pacotes)
        self.assertIn(("npm", "react-dom", "18.2.0"), pacotes)

    def test_gradle_lockfile(self):
        escrever(self.pasta, "gradle.lockfile",
                 "# comentário\norg.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath\nempty=\n")
        pacotes = vd.parse_gradle_lockfile(Path(self.pasta) / "gradle.lockfile")
        self.assertEqual(pacotes, [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_nuget_lock(self):
        escrever(self.pasta, "packages.lock.json", json.dumps({"version": 1, "dependencies": {
            "net8.0": {"Newtonsoft.Json": {"type": "Direct", "resolved": "12.0.1"},
                       "MeuProjeto": {"type": "Project"}}}}))
        pacotes = vd.parse_nuget_lock(Path(self.pasta) / "packages.lock.json")
        self.assertEqual(pacotes, [("NuGet", "Newtonsoft.Json", "12.0.1")])

    def test_sbom_sem_purl_nao_adivinha_ecossistema(self):
        escrever(self.pasta, "app.cdx.json", json.dumps({"components": [
            {"type": "library", "name": "sem-purl", "version": "1.0.0"},
            {"type": "library", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"},
        ]}))
        pacotes = vd.parse_cyclonedx(Path(self.pasta) / "app.cdx.json")
        self.assertEqual(pacotes, [("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")])

    def test_inventariar_deduplica(self):
        escrever(self.pasta, "package-lock.json", json.dumps({
            "packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
        escrever(self.pasta, "yarn.lock", 'lodash@^4.17.20:\n  version "4.17.20"\n')
        inventario = vd.inventariar([self.pasta])
        entradas = {(p["ecossistema"], p["nome"], p["versao"]) for p in inventario}
        self.assertEqual(list(entradas).count(("npm", "lodash", "4.17.20")), 1)


class TesteCvss(unittest.TestCase):
    def test_vetor_critico(self):
        score = vd.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        self.assertAlmostEqual(score, 9.8, places=1)

    def test_vetor_scope_alterado(self):
        score = vd.cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H")
        self.assertEqual(score, 10.0)

    def test_vetor_incompleto(self):
        self.assertIsNone(vd.cvss3_base_score("CVSS:3.1/AV:N/AC:L"))
        self.assertIsNone(vd.cvss3_base_score("não é um vetor"))

    def test_severidade_por_database_specific(self):
        vuln = {"id": "GHSA-x", "database_specific": {"severity": "HIGH"}}
        self.assertEqual(vd.severidade_de_vuln(vuln)[:2], ("alta", "alta"))
        vuln["database_specific"]["severity"] = "LOW"
        self.assertEqual(vd.severidade_de_vuln(vuln)[:2], ("baixa", "media"))

    def test_severidade_por_cvss(self):
        vuln = {"id": "GHSA-y", "severity": [
            {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
        self.assertEqual(vd.severidade_de_vuln(vuln)[0], "alta")
        self.assertEqual(vd.severidade_de_vuln(vuln)[1], "media")

    def test_severidade_sem_informacao(self):
        self.assertEqual(vd.severidade_de_vuln({"id": "GHSA-z"}), ("media", "baixa", None))

    def test_versao_corrigida_do_pacote_certo(self):
        vuln = {"affected": [
            {"package": {"name": "outro", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]},
            {"package": {"name": "lodash", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "4.17.21"}]}]},
        ]}
        self.assertEqual(vd._versao_corrigida(vuln, "lodash", "npm"), "4.17.21")

    def test_versao_corrigida(self):
        vuln = {"affected": [{"ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.4"}]}]}]}
        self.assertEqual(vd._versao_corrigida(vuln), "1.2.4")


VULN_EXEMPLO = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "summary": "Prototype pollution em lodash",
    "aliases": ["CVE-2020-8203"],
    "database_specific": {"severity": "HIGH"},
    "affected": [{"ranges": [{"events": [{"fixed": "4.17.21"}]}]}],
}


class TesteConsultaOsv(unittest.TestCase):
    def setUp(self):
        self.inventario = [
            {"ecossistema": "npm", "nome": "lodash", "versao": "4.17.20", "arquivo": "package-lock.json"},
            {"ecossistema": "npm", "nome": "seguro", "versao": "1.0.0", "arquivo": "package-lock.json"},
        ]

    def test_consulta_retorna_vulns_e_cache(self):
        resposta = {"results": [{"vulns": [VULN_EXEMPLO]}, {"vulns": []}]}
        with tempfile.TemporaryDirectory() as tmp:
            cache = str(Path(tmp) / "cache.json")
            with mock.patch.object(vd, "_post_osv", return_value=resposta) as post:
                resultado = vd.consultar_osv(self.inventario, cache=cache)
                self.assertEqual(len(resultado[0]), 1)
                self.assertEqual(resultado[1], [])
                self.assertEqual(post.call_count, 1)
                resultado2 = vd.consultar_osv(self.inventario, cache=cache)
                self.assertEqual(resultado2[0][0]["id"], VULN_EXEMPLO["id"])
                self.assertEqual(post.call_count, 1, "cache deveria evitar nova consulta")

    def test_querybatch_resumido_e_detalhado(self):
        # O querybatch real devolve apenas {id, modified}; o detalhe vem de /v1/vulns/{id}.
        resposta = {"results": [{"vulns": [{"id": VULN_EXEMPLO["id"], "modified": "2024-01-01T00:00:00Z"}]},
                                {"vulns": []}]}
        with mock.patch.object(vd, "_post_osv", return_value=resposta), \
                mock.patch.object(vd, "_get_vuln", return_value=VULN_EXEMPLO) as get:
            resultado = vd.consultar_osv(self.inventario, espera=0)
        get.assert_called_once()
        achados = vd.construir_achados(self.inventario, resultado)
        self.assertEqual(achados[0]["severidade"], "alta")
        self.assertIn("4.17.21", achados[0]["acao"])

    def test_consulta_sem_cache(self):
        resposta = {"results": [{"vulns": []}, {"vulns": []}]}
        with mock.patch.object(vd, "_post_osv", return_value=resposta):
            resultado = vd.consultar_osv(self.inventario)
            self.assertEqual(resultado[0], [])

    def test_construir_achados(self):
        vulnerabilidades = {0: [VULN_EXEMPLO]}
        achados = vd.construir_achados(self.inventario, vulnerabilidades)
        self.assertEqual(len(achados), 1)
        achado = achados[0]
        self.assertEqual(achado["categoria"], "DEPENDENCIA")
        self.assertEqual(achado["id"], "GHSA-xxxx-yyyy-zzzz")
        self.assertEqual(achado["severidade"], "alta")
        self.assertIn("4.17.21", achado["acao"])
        self.assertIn("CVE-2020-8203", achado["trecho"])


class TesteCli(unittest.TestCase):
    def test_modo_inventario_sem_rede(self):
        with tempfile.TemporaryDirectory() as tmp:
            escrever(tmp, "package-lock.json", json.dumps({
                "packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
            processo = subprocess.run(
                [sys.executable, str(CAMINHO), tmp, "--resumo", "--sem-cor"],
                capture_output=True, text=True, check=True)
            self.assertIn("pacotes: 1", processo.stdout)

    def test_modo_osv_com_mock(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory() as tmp:
            escrever(tmp, "package-lock.json", json.dumps({
                "packages": {"node_modules/lodash": {"version": "4.17.20"}}}))
            resposta = {"results": [{"vulns": [VULN_EXEMPLO]}]}
            saida = io.StringIO()
            with mock.patch.object(vd, "_post_osv", return_value=resposta):
                with contextlib.redirect_stdout(saida):
                    with self.assertRaises(SystemExit) as ctx:
                        vd.principal([tmp, "--osv", "--resumo", "--sem-cor", "--falhar-em", "nunca"])
            self.assertEqual(ctx.exception.code, 0)
            self.assertIn("achados: 1", saida.getvalue())


class TesteLockfileHostil(unittest.TestCase):
    def test_lockfile_malformado_nao_derruba_o_inventario(self):
        with tempfile.TemporaryDirectory() as tmp:
            escrever(tmp, "package-lock.json", "[1, 2, 3]")  # JSON válido, mas de tipo inesperado
            escrever(tmp, "composer.lock", "[" * 100000)      # aninhamento profundo
            (Path(tmp) / "sub").mkdir()
            escrever(str(Path(tmp) / "sub"), "Cargo.lock",
                     '[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            inventario = vd.inventariar([tmp])
        self.assertEqual([p["nome"] for p in inventario], ["serde"])

    def test_symlink_de_lockfile_e_ignorado(self):
        with tempfile.TemporaryDirectory() as tmp:
            fora = Path(tmp) / "fora.lock"
            fora.write_text('[[package]]\nname = "x"\nversion = "1.0.0"\n', encoding="utf-8")
            pasta = Path(tmp) / "projeto"
            pasta.mkdir()
            (pasta / "Cargo.lock").symlink_to(fora)
            self.assertEqual(vd.inventariar([str(pasta)]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
