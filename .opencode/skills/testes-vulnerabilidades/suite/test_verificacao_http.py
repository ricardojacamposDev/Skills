"""Testes da bateria HTTP.

Uso: python3 test_verificacao_http.py

Sobe servidores HTTP sintéticos em 127.0.0.1 (porta aleatória) e confere o que a
bateria aponta. Nenhum teste acessa a rede externa.
"""

import contextlib
import importlib.util
import io
import socket
import threading
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CAMINHO = Path(__file__).resolve().parent / "verificacao_http.py"
spec = importlib.util.spec_from_file_location("verificacao_http", CAMINHO)
vh = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vh)


class Vulneravel(BaseHTTPRequestHandler):
    """Servidor sintético com falhas propositais."""

    def log_message(self, *args):
        pass

    def responder(self, status, corpo="", headers=None):
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(corpo.encode("utf-8"))

    def do_OPTIONS(self):
        self.responder(200, headers={"Allow": "GET, POST, OPTIONS, TRACE, PUT"})

    def do_GET(self):
        caminho = self.path.split("?", 1)[0]
        origem = self.headers.get("Origin")
        if caminho == "/":
            headers = {
                "Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
                "Set-Cookie": "sessionid=abc; Path=/",
                "X-Powered-By": "Ficticio/1.0",
            }
            if origem:
                headers["Access-Control-Allow-Origin"] = origem
                headers["Access-Control-Allow-Credentials"] = "true"
            return self.responder(200, "<html>ok</html>", headers)
        if caminho == "/.git/HEAD":
            return self.responder(200, "ref: refs/heads/main\n")
        if caminho == "/metrics":
            return self.responder(200, "# HELP x y\n# TYPE x counter\nx 1\n")
        if caminho == "/logout" and "next=" in self.path:
            destino = self.path.split("next=", 1)[1]
            return self.responder(302, headers={"Location": destino})
        if caminho.startswith("/caminho-inexistente"):
            return self.responder(404, "Traceback (most recent call last):\n  File \"/var/www/app.py\"")
        return self.responder(404, "não encontrado")


class Endurecido(BaseHTTPRequestHandler):
    """Servidor sintético com os controles verificados presentes."""

    def log_message(self, *args):
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def do_GET(self):
        caminho = self.path.split("?", 1)[0]
        if caminho == "/.well-known/security.txt":
            corpo = b"Contact: mailto:seguranca@exemplo.invalid\nExpires: 2030-01-01T00:00:00Z\n"
            self.send_response(200)
            self.end_headers()
            self.wfile.write(corpo)
            return
        self.send_response(200 if caminho == "/" else 404)
        self.send_header("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Set-Cookie", "sessionid=abc; Path=/; HttpOnly; SameSite=Lax")
        self.end_headers()
        self.wfile.write(b"ok")


@contextlib.contextmanager
def servidor(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    srv.daemon_threads = True
    srv.server_version = ""
    srv.sys_version = ""
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_address[1]}"
    finally:
        srv.shutdown()
        srv.server_close()


def executar(url):
    bateria = vh.Bateria(url, espera=0, timeout=5, user_agent="teste")
    bateria.executar()
    return bateria


class TesteBateriaHttp(unittest.TestCase):
    def test_servidor_vulneravel(self):
        with servidor(Vulneravel) as url:
            bateria = executar(url)
        titulos = {a["titulo"] for a in bateria.achados}
        esperados = {
            "CSP permissiva para scripts",
            "Cookie de sessão sem HttpOnly (sessionid)",
            "CORS reflete origem arbitrária",
            "Página de erro vaza detalhes internos",
            "Método TRACE habilitado",
            "Repositório Git exposto (.git/HEAD)",
            "Métricas Prometheus expostas",
            "Redirecionamento aberto",
            "Banner de tecnologia exposto (x-powered-by)",
        }
        self.assertTrue(esperados <= titulos, f"não apontados: {esperados - titulos}")
        self.assertIsNone(bateria.interrompido)

    def test_servidor_endurecido(self):
        with servidor(Endurecido) as url:
            bateria = executar(url)
        relevantes = [a["titulo"] for a in bateria.achados if not a["titulo"].startswith("Banner")]
        self.assertEqual(relevantes, [])

    def test_tls_sem_servidor_nao_quebra(self):
        # Regressão: checar_tls levantava NameError (urlparse) em todo alvo HTTPS.
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            porta = s.getsockname()[1]
        bateria = vh.Bateria(f"https://127.0.0.1:{porta}", espera=0, timeout=2, user_agent="teste")
        bateria.checar_tls()
        self.assertEqual([a["titulo"] for a in bateria.achados], ["Falha ao negociar TLS"])


class TesteEscopoDeRedirect(unittest.TestCase):
    """O redirect só é seguido dentro da origem autorizada; controles do servidor são neutralizados."""

    def test_redirect_para_outra_origem_nao_e_seguido(self):
        externo_chamado = []

        class Externo(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                externo_chamado.append(self.path)
                self.send_response(200)
                self.end_headers()

        class Origem(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/interno":
                    self.send_response(200)
                    self.end_headers()
                    return
                destino = {"/mesmo": "/interno", "/fora": f"http://127.0.0.1:{porta_externa}/vazou"}[self.path]
                self.send_response(302)
                self.send_header("Location", destino)
                self.end_headers()

        ext = ThreadingHTTPServer(("127.0.0.1", 0), Externo)
        porta_externa = ext.server_address[1]
        org = ThreadingHTTPServer(("127.0.0.1", 0), Origem)
        for srv in (ext, org):
            threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            b = vh.Bateria(f"http://127.0.0.1:{org.server_address[1]}", 0, 5, "t")
            self.assertEqual(b.requisitar("/mesmo")[0], 200, "redirect na mesma origem é seguido")
            self.assertEqual(b.requisitar("/fora")[0], 302, "redirect para outra origem não é seguido")
            self.assertEqual(externo_chamado, [], "nenhuma requisição pode sair da origem autorizada")
        finally:
            for srv in (ext, org):
                srv.shutdown()
                srv.server_close()

    def test_limpar_remove_caracteres_de_controle(self):
        self.assertEqual(vh.limpar("a\x1b[31mb\x07c"), "a?[31mb?c")
        self.assertNotIn("\x1b", vh.limpar("x\x1b[2Jy"))
        self.assertNotIn("\x07", vh.limpar("bel\x07"))


class TesteRecusas(unittest.TestCase):
    def rodar(self, argv):
        saida = io.StringIO()
        with contextlib.redirect_stdout(saida), contextlib.redirect_stderr(saida):
            with self.assertRaises(SystemExit) as ctx:
                vh.main(argv)
        return ctx.exception.code

    def test_sem_autorizado(self):
        codigo = self.rodar(["--url", "http://127.0.0.1:9"])
        self.assertIn("recusa", str(codigo))

    def test_faixas_locais(self):
        for host in ("127.0.0.1", "10.1.2.3", "192.168.0.5", "172.20.0.1", "::1", "localhost", "app.localhost"):
            self.assertTrue(vh.host_eh_local(host), host)
        # Faixas de documentação/reservadas não são ambiente local (ipaddress.is_private diz que sim).
        for host in ("198.51.100.10", "203.0.113.5", "192.0.2.1", "8.8.8.8", "100.64.0.1"):
            self.assertFalse(vh.host_eh_local(host), host)

    def test_sufixo_local_so_vale_se_resolver_para_ip_local(self):
        def resolve_para(ip):
            return lambda host, porta: [(2, 1, 6, "", (ip, 0))]
        with mock.patch.object(vh.socket, "getaddrinfo", resolve_para("203.0.113.9")):
            self.assertFalse(vh.host_eh_local("app.internal"), ".internal resolvendo para IP público")
            self.assertFalse(vh.host_eh_local("app.local"))
        with mock.patch.object(vh.socket, "getaddrinfo", resolve_para("10.0.0.7")):
            self.assertTrue(vh.host_eh_local("app.internal"))

    def test_host_externo_sem_forcar(self):
        codigo = self.rodar(["--url", "http://198.51.100.10", "--autorizado"])
        self.assertIn("recusa", str(codigo))


if __name__ == "__main__":
    unittest.main(verbosity=2)
