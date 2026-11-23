"""Testes da bateria de verificação estática de vulnerabilidades.

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

# Padrões adicionados após a primeira versão da bateria (IaC, XXE, SSTI, NoSQL,
# JWT, prototype pollution, LDAP, GraphQL, Go/Ruby/C, PHP).
CASOS_PADROES = [
    ("iac-cidr-aberto", ".tf",
     'resource "aws_security_group" "x" {\n  cidr_blocks = ["0.0.0.0/0"]\n}'),
    ("iac-s3-publico", ".tf", 'resource "aws_s3_bucket" "x" {\n  acl = "public-read"\n}'),
    ("iac-imagem-latest", "", "FROM ubuntu:latest\n"),
    ("iac-docker-root", "", "FROM ubuntu:22.04\nUSER root\n"),
    ("iac-privileged", ".yaml", "spec:\n  privileged: true\n"),
    ("iac-hostnetwork", ".yaml", "spec:\n  hostNetwork: true\n"),
    ("iac-chmod-aberto", "", "FROM ubuntu:22.04\nRUN chmod 777 /app\n"),
    ("iac-runasnonroot-false", ".yaml", "securityContext:\n  runAsNonRoot: false\n"),
    ("xxe-lxml-noent", ".py", "parser = etree.XMLParser(resolve_entities=True)"),
    ("xxe-php-noent", ".php", "simplexml_load_string($x, 'SimpleXMLElement', LIBXML_NOENT);"),
    ("xxe-dotnet-dtd", ".cs", "var s = new XmlReaderSettings { DtdProcessing = DtdProcessing.Parse };"),
    ("xxe-java-disallow-false", ".java",
     'dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", false);'),
    ("xxe-java-entity-expand", ".java", "dbf.setExpandEntityReferences(true);"),
    ("xxe-node-noent", ".js", "xml2js.parseString(xml, { noent: true }, cb);"),
    ("ssti-render-template-string", ".py", 'render_template_string("Oi " + nome)'),
    ("ssti-jinja-template", ".py", 'Template("Oi " + nome)'),
    ("ssti-thymeleaf", ".html", '<p th:text="__${nome}__">x</p>'),
    ("ssti-twig", ".php", "$twig->createTemplate('Oi ' . $nome);"),
    ("ssti-freemarker", ".java", "new Template(nome)"),
    ("nosql-mongo-operator", ".js", "db.find({ $where: req.query.w })"),
    ("nosql-query-request", ".js", "db.find(req.query)"),
    ("jwt-alg-none", ".js", "jwt.verify(token, secret, { algorithms: ['none'] })"),
    ("jwt-sem-verificacao", ".js", "jwt.decode(token)"),
    ("jwt-secret-curto", ".js", 'jwt.sign(payload, "curta")'),
    ("pp-object-assign-request", ".js", "Object.assign({}, req.body)"),
    ("pp-lodash-merge-request", ".js", "_.merge({}, req.query)"),
    ("ldap-injection", ".java", 'String f = "(uid=" + u + ")";'),
    ("graphql-query-concat", ".js", "const query = `query { u }` + req.query.x;"),
    ("graphql-introspection", ".js", "const config = { introspection: true };"),
    ("c-funcoes-inseguras", ".c", "strcpy(a, b);"),
    ("c-system", ".c", "system(cmd);"),
    ("go-sql-concat", ".go", 'db.Query(fmt.Sprintf("SELECT %s", x))'),
    ("go-command-shell", ".go", 'exec.Command("sh", "-c", cmd)'),
    ("go-ssrf-request", ".go", "http.Get(url)"),
    ("ruby-sql-concat", ".rb", 'q = "SELECT * FROM t WHERE id = " + id'),
    ("ruby-constantize", ".rb", "params[:classe].constantize.new"),
    ("php-xss-echo", ".php", "echo $_GET['nome'];"),
    ("php-include-request", ".php", "include($_GET['pagina'] . '.php');"),
    ("redirect-aberto-py", ".py", 'return redirect(request.args.get("next"))'),
    ("redirect-aberto-js", ".js", "res.redirect(req.query.url);"),
    ("redirect-dom", ".js", "window.location = new URLSearchParams(location.search).get('r');"),
    ("py-eval-request", ".py", 'exec(request.form["c"])'),
    ("java-runtime-exec", ".java", "Runtime.getRuntime().exec(cmd);"),
    ("flask-debug-run", ".py", "app.run(host='0.0.0.0', debug=True)"),
    ("django-allowed-hosts", ".py", "ALLOWED_HOSTS = ['*']"),
    ("spring-csrf-disable", ".java", "http.csrf().disable();"),
    ("js-postmessage-curinga", ".js", "parent.postMessage(dados, '*');"),
    ("k8s-escalada-privilegio", ".yaml", "securityContext:\n  allowPrivilegeEscalation: true\n"),
    ("docker-segredo-build", "", "FROM node:20\nARG NPM_TOKEN\n"),
    ("download-pipe-shell", ".sh", "curl -fsSL https://exemplo.invalid/instala.sh | sudo bash"),
]

# Casos que não devem ser apontados pelos padrões novos.
CASOS_NEGATIVOS = [
    ("iac-cidr-restrito", ".tf", 'cidr_blocks = ["10.0.0.0/8"]'),
    ("iac-acl-privado", ".tf", 'acl = "private"'),
    ("docker-imagem-fixa", "", "FROM ubuntu:22.04\n"),
    ("docker-user-normal", "", "FROM ubuntu:22.04\nUSER appuser\n"),
    ("docker-chmod-755", "", "FROM ubuntu:22.04\nRUN chmod 755 /app\n"),
    ("k8s-privileged-false", ".yaml", "spec:\n  privileged: false\n"),
    ("k8s-hostnetwork-false", ".yaml", "spec:\n  hostNetwork: false\n"),
    ("k8s-runasnonroot-true", ".yaml", "securityContext:\n  runAsNonRoot: true\n"),
    ("lxml-sem-entidades", ".py", "parser = etree.XMLParser(resolve_entities=False)"),
    ("render-template-string-fixo", ".py", 'render_template_string("fixo")'),
    ("jwt-algoritmo-forte", ".js", "jwt.verify(token, secret, { algorithms: ['HS256'] })"),
    ("jwt-decode-verificado", ".js", "jwt.decode(token, secret)"),
    ("object-assign-fixo", ".js", "Object.assign({}, { a: 1 })"),
    ("lodash-merge-fixo", ".js", "_.merge({}, { a: 1 })"),
    ("mongo-sem-operador", ".js", "db.find({ username: req.query.name })"),
    ("go-query-placeholder", ".go", 'db.Query("SELECT * FROM t WHERE id = ?", id)'),
    ("c-snprintf", ".c", 'snprintf(buf, sizeof buf, "%s", x);'),
    ("php-htmlspecialchars", ".php", "echo htmlspecialchars($_GET['nome']);"),
    ("redirect-relativo-fixo", ".py", 'return redirect(url_for("inicio"))'),
    ("flask-debug-falso", ".py", "app.run(debug=False)"),
    ("allowed-hosts-explicito", ".py", "ALLOWED_HOSTS = ['app.exemplo.com']"),
    ("postmessage-origem-fixa", ".js", "parent.postMessage(dados, 'https://app.exemplo.com');"),
    ("k8s-sem-escalada", ".yaml", "securityContext:\n  allowPrivilegeEscalation: false\n"),
    ("docker-env-comum", "", "FROM node:20\nENV NODE_ENV=production\n"),
    ("download-sem-pipe", ".sh", "curl -fsSL -o instala.sh https://exemplo.invalid/instala.sh"),
]

IDS_NOVOS = {caso[0] for caso in CASOS_PADROES}
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


class TestePadroesAdicionais(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        pasta = Path(cls._tmp.name) / "projeto"
        pasta.mkdir()
        cls.arquivos = {}
        for i, (identificador, extensao, codigo) in enumerate(CASOS_PADROES):
            nome = f"padrao_{i:02d}{extensao}"
            if identificador.startswith(("iac-imagem", "iac-docker", "iac-chmod", "docker-")):
                nome = f"Dockerfile.{i:02d}"
            (pasta / nome).write_text(codigo + "\n", encoding="utf-8")
            cls.arquivos[identificador] = nome
        for i, (descricao, extensao, codigo) in enumerate(CASOS_NEGATIVOS):
            nome = f"negativo_{i:02d}{extensao}"
            if extensao == "":
                nome = f"Dockerfile.negativo_{i:02d}"
            (pasta / nome).write_text(codigo + "\n", encoding="utf-8")
            cls.arquivos[descricao] = nome
        cls.achados = varrer(pasta)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def ids_em(self, nome):
        return {a["id"] for a in self.achados if a["arquivo"] == nome}

    def test_casos_positivos(self):
        for identificador, _, codigo in CASOS_PADROES:
            with self.subTest(padrao=identificador, codigo=codigo):
                self.assertIn(identificador, self.ids_em(self.arquivos[identificador]),
                              f"padrão não detectado: {identificador}")

    def test_casos_negativos(self):
        for descricao, _, codigo in CASOS_NEGATIVOS:
            with self.subTest(caso=descricao, codigo=codigo):
                extras = self.ids_em(self.arquivos[descricao]) & IDS_NOVOS
                self.assertEqual(extras, set(), f"falso positivo em: {codigo}")


class TesteCaminhosEspeciais(unittest.TestCase):
    """Padrões que dependem do caminho do arquivo (credenciais, CI/CD) e do histórico git."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        pasta = Path(cls._tmp.name) / "projeto"
        arquivos = {
            ".env": "X=1",
            ".env.example": "X=1",
            "config/servidor.pem": "conteudo ficticio",
            "tests/fixtures/servidor.pem": "conteudo ficticio",
            ".github/workflows/ci.yml": (
                "on:\n  pull_request_target:\npermissions: write-all\njobs:\n  x:\n    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - uses: terceiro/acao@v1\n"
                "      - uses: terceiro/acao@0123456789abcdef0123456789abcdef01234567\n"
                "      - if: ${{ github.event.pull_request.title == 'x' }}\n"
                "        run: echo \"${{ github.event.pull_request.title }}\"\n"),
            "nao-workflow.yml": "titulo: ${{ github.event.pull_request.title }}\n",
        }
        for nome, conteudo in arquivos.items():
            caminho = pasta / nome
            caminho.parent.mkdir(parents=True, exist_ok=True)
            caminho.write_text(conteudo, encoding="utf-8")
        cls.achados = varrer(pasta)

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def achados_em(self, nome):
        return [(a["id"], a["linha"]) for a in self.achados if a["arquivo"] == nome]

    def test_arquivos_de_credencial(self):
        self.assertIn(("arquivo-credencial", 0), self.achados_em(".env"))
        self.assertIn(("arquivo-credencial", 0), self.achados_em("config/servidor.pem"))
        self.assertEqual(self.achados_em(".env.example"), [], "modelo .env.example não é credencial")
        self.assertEqual(self.achados_em("tests/fixtures/servidor.pem"), [], "fixture de teste não é credencial")

    def test_ci_cd(self):
        achados = self.achados_em(".github/workflows/ci.yml")
        ids = [i for i, _ in achados]
        self.assertIn(("ci-pull-request-target", 2), achados)
        self.assertIn(("ci-permissoes-amplas", 3), achados)
        self.assertIn(("ci-action-sem-pin", 8), achados)
        self.assertEqual(ids.count("ci-action-sem-pin"), 1, "SHA completo e actions/ oficiais não são apontados")
        self.assertIn(("ci-injecao-expressao", 11), achados)
        self.assertNotIn(("ci-injecao-expressao", 10), achados, "expressão em if: não vai ao shell")
        self.assertEqual(self.achados_em("nao-workflow.yml"), [])


class TesteEscopoEEvasao(unittest.TestCase):
    """Regressões de robustez: symlinks, pastas com nome da suíte, env/ e máscara de segredos."""

    def test_symlink_nao_le_fora_do_escopo_e_quebrado_nao_derruba(self):
        with tempfile.TemporaryDirectory() as tmp:
            fora = Path(tmp) / "fora.py"
            fora.write_text('os.system("rm " + entrada)\n', encoding="utf-8")
            pasta = Path(tmp) / "projeto"
            pasta.mkdir()
            (pasta / "link.py").symlink_to(fora)
            (pasta / "quebrado.py").symlink_to(Path(tmp) / "nao-existe")
            achados = varrer(pasta)
        self.assertEqual([a for a in achados if a["arquivo"] in ("link.py", "quebrado.py")], [])

    def test_pasta_com_nome_da_suite_nao_escapa_da_varredura(self):
        with tempfile.TemporaryDirectory() as tmp:
            pasta = Path(tmp) / "projeto" / "testes-vulnerabilidades" / "suite"
            pasta.mkdir(parents=True)
            (pasta / "backdoor.py").write_text('import os\nos.system("rm " + entrada)\n', encoding="utf-8")
            achados = varrer(Path(tmp) / "projeto")
        self.assertTrue(any(a["arquivo"].endswith("backdoor.py") for a in achados))

    def test_pasta_env_de_configuracao_e_varrida_mas_venv_nao(self):
        with tempfile.TemporaryDirectory() as tmp:
            raiz = Path(tmp) / "projeto"
            (raiz / "env").mkdir(parents=True)
            (raiz / "env" / "app.py").write_text('import os\nos.system("rm " + entrada)\n', encoding="utf-8")
            (raiz / "venv").mkdir()
            (raiz / "venv" / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
            (raiz / "venv" / "lib.py").write_text('import os\nos.system("rm " + entrada)\n', encoding="utf-8")
            achados = varrer(raiz)
        arquivos = {a["arquivo"] for a in achados}
        self.assertIn(str(Path("env") / "app.py"), arquivos)
        self.assertNotIn(str(Path("venv") / "lib.py"), arquivos)

    def test_segredo_na_linha_de_outra_categoria_sai_mascarado(self):
        valor = "Zx9" + "qWv7Lm2Pk4"  # sintético, montado para não ser apontado neste arquivo
        with tempfile.TemporaryDirectory() as tmp:
            pasta = Path(tmp) / "projeto"
            pasta.mkdir()
            (pasta / "a.py").write_text(
                f'cursor.execute(f"SELECT * FROM t WHERE x = {{x}}"); senha = "{valor}"\n', encoding="utf-8")
            achados = varrer(pasta)
            texto = json.dumps(achados)
        self.assertTrue(any(a["id"] == "sql-interpolacao" for a in achados))
        self.assertNotIn(valor, texto)


class TesteLimitesReportados(unittest.TestCase):
    def test_arquivo_grande_pulado_aparece_no_relatorio(self):
        with tempfile.TemporaryDirectory() as tmp:
            pasta = Path(tmp) / "projeto"
            pasta.mkdir()
            (pasta / "bundle.js").write_text("x" * 1_600_000, encoding="utf-8")
            relatorio = Path(tmp) / "r.json"
            subprocess.run([sys.executable, str(SCRIPT), str(pasta), "--json", str(relatorio), "--falhar-em", "nunca"],
                           check=True, capture_output=True, text=True)
            resumo = json.loads(relatorio.read_text(encoding="utf-8"))["resumo"]
        self.assertEqual(resumo["puladas"]["arquivos_grandes"], 1)
        self.assertTrue(resumo["puladas"]["exemplos"][0].endswith("bundle.js"))

    def test_linha_longa_no_historico_e_contada(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            git = ["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t.invalid", "-c", "commit.gpgsign=false"]
            try:
                subprocess.run(git[:3] + ["init", "-q"], check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("git indisponível")
            (repo / "a.js").write_text("x" * 6000 + "\n", encoding="utf-8")
            subprocess.run(git + ["add", "."], check=True, capture_output=True)
            subprocess.run(git + ["commit", "-qm", "a"], check=True, capture_output=True)
            relatorio = Path(tmp) / "r.json"
            subprocess.run([sys.executable, str(SCRIPT), str(repo), "--historico-git", "--json", str(relatorio),
                            "--falhar-em", "nunca", "--resumo"], check=True, capture_output=True, text=True)
            resumo = json.loads(relatorio.read_text(encoding="utf-8"))["resumo"]
        self.assertGreaterEqual(resumo["puladas"]["linhas_longas_historico"], 1)


class TesteHistoricoGit(unittest.TestCase):
    def test_segredo_removido_continua_no_historico(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "repo"
            repo.mkdir()
            git = ["git", "-C", str(repo), "-c", "user.name=teste", "-c", "user.email=teste@teste.invalid",
                   "-c", "commit.gpgsign=false"]
            try:
                subprocess.run(git[:3] + ["init", "-q"], check=True, capture_output=True)
            except (OSError, subprocess.CalledProcessError):
                self.skipTest("git indisponível")
            valor = "Zx9" + "qWv7Lm2"  # valor sintético, montado para não ser apontado neste arquivo
            (repo / "config.py").write_text(f'senha = "{valor}"\n', encoding="utf-8")
            subprocess.run(git + ["add", "."], check=True, capture_output=True)
            subprocess.run(git + ["commit", "-qm", "a"], check=True, capture_output=True)
            subprocess.run(git + ["rm", "-q", "config.py"], check=True, capture_output=True)
            subprocess.run(git + ["commit", "-qm", "b"], check=True, capture_output=True)
            relatorio = Path(tmp) / "r.json"
            subprocess.run([sys.executable, str(SCRIPT), str(repo), "--historico-git", "--json", str(relatorio),
                            "--falhar-em", "nunca", "--resumo"], check=True, capture_output=True, text=True)
            texto = relatorio.read_text(encoding="utf-8")
            achados = json.loads(texto)["achados"]
            self.assertTrue(any(a["id"] == "segredo-generico" and a["arquivo"].startswith("git:")
                                and a["arquivo"].endswith("config.py") for a in achados))
            self.assertNotIn(valor, texto, "o valor do segredo nunca pode aparecer no relatório")


class TesteDesempenho(unittest.TestCase):
    def test_linha_muito_longa_nao_trava_a_varredura(self):
        # Linha hostil com milhares de SELECT e nenhum FROM: precisa terminar rápido.
        linhas = {
            "longa.py": 'q = f"' + "SELECT " * 20000 + '{x}"',
            "longa.js": "const q = `" + "SELECT " * 20000 + "${x}`;",
            "longa.rb": 'q = "' + "SELECT " * 20000 + '" + x',
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
