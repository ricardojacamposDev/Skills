"""Testes da detecção de injeção de SQL em verificacao_estatica.py.

Uso: python3 test_verificacao_estatica.py

Cada caso grava um arquivo fictício numa pasta temporária, roda a varredura
nele e confere qual padrão foi (ou não) apontado. Os exemplos são código de
mentira, nunca executado. Este arquivo não é varrido pela própria bateria,
porque ela ignora a pasta testes-vulnerabilidades/suite.
"""

import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "verificacao_estatica.py"

# (descrição, extensão, linha de código, id esperado ou None quando nada deve ser apontado)
CASOS = [
    # Python: f-string guardada numa variável antes de chegar ao banco
    ("f-string em variável com aspas internas", ".py",
     "sql = f\"SELECT nome, email FROM clientes WHERE nome = '{nome}'\"", "sql-interpolacao"),
    ("f-string em variável com aspas simples", ".py",
     "sql = f'DELETE FROM pedidos WHERE id = {pedido_id}'", "sql-interpolacao"),
    ("f-string de UPDATE em variável", ".py",
     "q = f\"UPDATE usuarios SET nome = '{nome}' WHERE id = {uid}\"", "sql-interpolacao"),
    ("f-string direto no execute", ".py",
     "cur.execute(f\"SELECT * FROM t WHERE id = {item_id}\")", "sql-interpolacao"),
    ("f-string direto no execute com aspas internas", ".py",
     "cur.execute(f\"SELECT * FROM t WHERE nome = '{nome}'\")", "sql-interpolacao"),
    ("f-string com prefixo rf", ".py",
     "q = rf\"SELECT * FROM t WHERE id = {item_id}\"", "sql-interpolacao"),
    # Python: concatenação e formatação
    ("concatenação com aspas internas", ".py",
     "q = \"SELECT * FROM t WHERE nome = '\" + nome + \"'\"", "sql-concatenacao"),
    ("concatenação simples", ".py",
     "q = \"SELECT * FROM t WHERE id = \" + item_id", "sql-concatenacao"),
    ("str.format", ".py",
     "q = \"SELECT * FROM t WHERE nome = '{}'\".format(nome)", "sql-concatenacao"),
    ("operador %", ".py",
     "q = \"SELECT * FROM t WHERE id = %s\" % item_id", "sql-concatenacao"),
    # JavaScript: template literal em variável
    ("template literal em variável", ".js",
     "const q = `SELECT * FROM t WHERE id = ${id}`;", "sql-template-literal"),
    ("template literal com aspas internas", ".ts",
     "const q = `SELECT * FROM t WHERE nome = '${nome}'`;", "sql-template-literal"),
    ("template literal direto no query", ".js",
     "db.query(`DELETE FROM t WHERE id = ${id}`);", "sql-template-literal"),
    # Formas seguras: nada deve ser apontado
    ("parâmetro com ?", ".py",
     "cur.execute(\"SELECT * FROM t WHERE id = ?\", (item_id,))", None),
    ("parâmetro com %s passado ao driver", ".py",
     "cur.execute(\"SELECT * FROM t WHERE nome = %s\", (nome,))", None),
    ("f-string sem SQL", ".py",
     "print(f\"Total: {n} itens\")", None),
    ("f-string com SQL sem interpolação", ".py",
     "q = f\"SELECT * FROM t WHERE x = '{{fixo}}'\"", None),
    ("template com tag sql (parametrizado)", ".js",
     "const r = await sql`SELECT * FROM t WHERE id = ${id}`;", None),
    ("template com tag tipada sql<Row> (parametrizado)", ".ts",
     "const r = await sql<Row>`SELECT * FROM t WHERE id = ${id}`;", None),
    ("template com tag $queryRaw (parametrizado)", ".ts",
     "const r = await prisma.$queryRaw`SELECT * FROM t WHERE id = ${id}`;", None),
    ("template literal sem SQL", ".js",
     "const msg = `Olá, ${nome}`;", None),
]

IDS_SQL = {"sql-interpolacao", "sql-template-literal", "sql-concatenacao", "orm-raw-interp", "java-query-concat"}


def varrer(pasta):
    relatorio = Path(pasta) / "relatorio.json"
    subprocess.run(
        [sys.executable, str(SCRIPT), str(pasta), "--json", str(relatorio), "--falhar-em", "nunca", "--resumo"],
        check=True, capture_output=True, text=True,
    )
    return json.loads(relatorio.read_text(encoding="utf-8"))["achados"]


class TesteDeteccaoSQL(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        pasta = Path(cls._tmp.name) / "projeto"
        pasta.mkdir()
        cls.arquivos = {}
        for i, (descricao, extensao, codigo, _) in enumerate(CASOS):
            nome = f"caso_{i:02d}{extensao}"
            (pasta / nome).write_text(codigo + "\n", encoding="utf-8")
            cls.arquivos[descricao] = nome
        cls.achados = varrer(pasta)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def ids_sql_em(self, nome):
        return sorted(a["id"] for a in self.achados if a["arquivo"] == nome and a["id"] in IDS_SQL)

    def test_casos(self):
        for descricao, _, codigo, esperado in CASOS:
            with self.subTest(caso=descricao):
                encontrados = self.ids_sql_em(self.arquivos[descricao])
                if esperado is None:
                    self.assertEqual(encontrados, [], f"falso positivo em: {codigo}")
                else:
                    self.assertEqual(encontrados, [esperado], f"não detectado (ou duplicado) em: {codigo}")


class TesteDesempenho(unittest.TestCase):
    def test_linha_muito_longa_nao_trava_a_varredura(self):
        # Linha hostil com milhares de SELECT e nenhum FROM: precisa terminar rápido.
        linhas = {
            "longa.py": 'q = f"' + "SELECT " * 20000 + '{x}"',
            "longa.js": "const q = `" + "SELECT " * 20000 + "${x}`;",
        }
        with tempfile.TemporaryDirectory() as tmp:
            pasta = Path(tmp) / "projeto"
            pasta.mkdir()
            for nome, conteudo in linhas.items():
                (pasta / nome).write_text(conteudo + "\n", encoding="utf-8")
            inicio = time.perf_counter()
            varrer(pasta)
            duracao = time.perf_counter() - inicio
        self.assertLess(duracao, 5, f"varredura levou {duracao:.1f}s em linhas longas")


if __name__ == "__main__":
    unittest.main(verbosity=2)
