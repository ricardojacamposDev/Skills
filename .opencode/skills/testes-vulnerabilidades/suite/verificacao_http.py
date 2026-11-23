#!/usr/bin/env python3
"""Bateria de checagens HTTP de segurança em ambiente controlado.

 Executa apenas requisições GET/OPTIONS não destrutivas contra uma URL
 declarada como autorizada. Verifica headers, cookies, CORS, TLS e vazamento
 em páginas de erro. Interrompe diante de respostas 5xx. Nunca use contra
 produção ou sistemas de terceiros sem autorização explícita.
"""

import argparse
import datetime
import ipaddress
import json
import random
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

SEVERIDADES = {"baixa": 0, "media": 1, "alta": 2}
CONFIANCAS = {"baixa": 0, "media": 1, "alta": 2}
HSTS_MINIMO = 15552000

PADRAO_ERRO = re.compile(
    r"(Traceback \(most recent call last\)|at [\w.$]+\([a-zA-Z0-9_$.]+\.java:\d+\)|"
    r"Stack trace|stacktrace|SQLSTATE|Warning: [A-Za-z_]+ in /|"
    r"Exception|/home/[\w.-]+/|/var/www/|C:\\\\Users\\\\|D:\\\\wamp|"
    r"at\s+\w+\s+\(.*\.php:\d+\)|System\.NullReferenceException|segmentation fault)",
    re.IGNORECASE,
)

class SemRedirect(urllib.request.HTTPRedirectHandler):
    """Impede seguimento automático de redirect, para inspecionar o Location."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _origem(url):
    p = urllib.parse.urlparse(url)
    porta = p.port or {"http": 80, "https": 443}.get(p.scheme)
    return (p.scheme, (p.hostname or "").lower(), porta)


class RedirectMesmaOrigem(urllib.request.HTTPRedirectHandler):
    """Segue redirects só dentro da origem autorizada.

    A autorização cobre apenas o host informado em --url: seguir um redirect para outro host
    (produção, SSO, terceiros, ftp://) enviaria requisições fora do escopo. Redirect para outra
    origem não é seguido; a resposta 3xx é devolvida como está.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if _origem(newurl) != _origem(req.full_url):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_CONTROLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def limpar(texto):
    """Remove caracteres de controle (ex.: sequências ANSI) vindos do servidor sondado."""
    return _CONTROLE.sub("?", str(texto))


REDES_LOCAIS = [ipaddress.ip_network(r) for r in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
    "::1/128", "fc00::/7", "fe80::/10",
)]


def ip_eh_local(ip):
    # ipaddress.is_private também considera faixas de documentação/reservadas
    # (ex.: 198.51.100.0/24) que não são ambiente local; por isso a lista explícita.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return any(ip.version == rede.version and ip in rede for rede in REDES_LOCAIS)


def host_eh_local(host):
    try:
        return ip_eh_local(ipaddress.ip_address(host))
    except ValueError:
        pass
    # Só "localhost" e "*.localhost" (loopback por RFC 6761) valem sem resolver. Sufixos como
    # ".local"/".internal" não garantem nada: o nome pode resolver para IP público.
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    ips = []
    for info in infos:
        try:
            ips.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
        except ValueError:
            continue
    # Todos os endereços resolvidos precisam ser locais.
    return bool(ips) and all(ip_eh_local(ip) for ip in ips)

class Bateria:
    def __init__(self, url, espera, timeout, user_agent, pular_rotas=False, pular_open_redirect=False):
        self.url = url.rstrip("/")
        self.espera = espera
        self.timeout = timeout
        self.user_agent = user_agent
        self.pular_rotas = pular_rotas
        self.pular_open_redirect = pular_open_redirect
        self.achados = []
        self.requisicoes = 0
        self.interrompido = None
        self.opener_sem_redirect = urllib.request.build_opener(SemRedirect())
        self.opener_mesma_origem = urllib.request.build_opener(RedirectMesmaOrigem())

    def achado(self, categoria, titulo, severidade, confianca, detalhe, acao, cwe=""):
        self.achados.append(dict(
            categoria=categoria, id=None, titulo=limpar(titulo), severidade=severidade,
            confianca=confianca, cwe=cwe, local=self.url, detalhe=limpar(detalhe), acao=acao,
        ))

    def requisitar(self, caminho="/", headers=None, metodo="GET", seguir_redirect=True):
        alvo = self.url + caminho
        pedido = urllib.request.Request(alvo, method=metodo, headers={"User-Agent": self.user_agent})
        for k, v in (headers or {}).items():
            pedido.add_header(k, v)
        self.requisicoes += 1
        abridor = self.opener_mesma_origem.open if seguir_redirect else self.opener_sem_redirect.open
        try:
            with abridor(pedido, timeout=self.timeout) as resposta:
                corpo = resposta.read(200_000).decode("utf-8", errors="replace")
                return resposta.status, dict(resposta.headers.items()), corpo
        except urllib.error.HTTPError as e:
            with e:
                corpo = e.read(200_000).decode("utf-8", errors="replace")
                return e.code, dict(e.headers.items()), corpo
        finally:
            time.sleep(self.espera)

    def parar_se_erro_servidor(self, status):
        if status >= 500:
            self.interrompido = f"resposta {status} — bateria interrompida por critério de parada"
            return True
        return False

    def checar_headers(self):
        status, headers, _ = self.requisitar("/")
        minusculas = {k.lower(): v for k, v in headers.items()}
        if self.parar_se_erro_servidor(status):
            return minusculas, headers
        csp = minusculas.get("content-security-policy", "")
        if not csp:
            self.achado("CABECALHOS", "Content-Security-Policy ausente", "baixa", "alta",
                        "Sem CSP, injeções de script dependem apenas do escape da aplicação.",
                        "Defina CSP restritiva com nonces/hashes e verifique violações antes de endurecer.", "CWE-693")
        else:
            self.checar_qualidade_csp(csp)
        if "x-frame-options" not in minusculas and "frame-ancestors" not in csp:
            self.achado("CABECALHOS", "Proteção contra clickjacking ausente", "baixa", "alta",
                        "Nem X-Frame-Options nem frame-ancestors na CSP.",
                        "Use frame-ancestors na CSP ou X-Frame-Options: DENY/SAMEORIGIN.", "CWE-1021")
        if "x-content-type-options" not in minusculas:
            self.achado("CABECALHOS", "X-Content-Type-Options ausente", "baixa", "alta",
                        "Permite sniffing de MIME do conteúdo servido.",
                        "Envie X-Content-Type-Options: nosniff.", "CWE-430")
        if "referrer-policy" not in minusculas:
            self.achado("CABECALHOS", "Referrer-Policy ausente", "baixa", "alta",
                        "URLs visitadas podem vazar para terceiros via Referer.",
                        "Defina Referrer-Policy: strict-origin-when-cross-origin ou mais restritiva.", "CWE-200")
        if self.url.startswith("https://"):
            hsts = minusculas.get("strict-transport-security", "")
            if not hsts:
                self.achado("CABECALHOS", "HSTS ausente em origem HTTPS", "media", "alta",
                            "Sem HSTS, downgrade para HTTP permanece possível no cliente.",
                            "Envie Strict-Transport-Security com max-age >= 15552000 e avalie includeSubDomains.", "CWE-319")
            else:
                m = re.search(r"max-age=(\d+)", hsts)
                if not m or int(m.group(1)) < HSTS_MINIMO:
                    self.achado("CABECALHOS", "HSTS com max-age insuficiente", "baixa", "alta",
                                f"Valor atual: {hsts!r}.",
                                "Aumente max-age para pelo menos 15552000 segundos.", "CWE-319")
        for nome in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
            if nome in minusculas:
                self.achado("EXPOSICAO", f"Banner de tecnologia exposto ({nome})", "baixa", "alta",
                            f"{nome}: {minusculas[nome]!r} facilita mapeamento de versões vulneráveis.",
                            "Remova ou minimize banners de implementação.", "CWE-200")
        return minusculas, headers

    def checar_qualidade_csp(self, csp):
        """Aponta diretivas que anulam a proteção da CSP contra XSS."""
        diretivas = {}
        for parte in csp.split(";"):
            tokens = parte.strip().split()
            if tokens:
                diretivas[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
        scripts = diretivas.get("script-src", diretivas.get("default-src"))
        if scripts is None:
            self.achado("CABECALHOS", "CSP sem script-src nem default-src", "baixa", "alta",
                        f"CSP: {csp[:160]!r}", "Inclua default-src 'self' (ou script-src explícito).", "CWE-693")
            return
        problemas = []
        tem_nonce_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in scripts)
        if "'unsafe-inline'" in scripts and not tem_nonce_hash:
            problemas.append("'unsafe-inline'")
        if "'unsafe-eval'" in scripts:
            problemas.append("'unsafe-eval'")
        if any(t in ("*", "http:", "https:", "data:") for t in scripts):
            problemas.append("origem curinga (*, http:, https: ou data:)")
        if problemas:
            self.achado("CABECALHOS", "CSP permissiva para scripts", "baixa", "alta",
                        f"script-src/default-src contém {', '.join(problemas)}.",
                        "Use nonces/hashes e origens explícitas; sem isso a CSP não barra XSS.", "CWE-693")

    def checar_redirect_https(self):
        """Com alvo HTTPS, confere se a versão HTTP redireciona para HTTPS."""
        partes = urllib.parse.urlparse(self.url)
        if partes.port not in (None, 443):
            return
        alvo_http = urllib.parse.urlunparse(("http", partes.hostname, partes.path or "/", "", "", ""))
        pedido = urllib.request.Request(alvo_http, headers={"User-Agent": self.user_agent})
        self.requisicoes += 1
        try:
            with self.opener_sem_redirect.open(pedido, timeout=self.timeout) as resposta:
                status, headers = resposta.status, dict(resposta.headers.items())
        except urllib.error.HTTPError as e:
            with e:
                status, headers = e.code, dict(e.headers.items())
        except (urllib.error.URLError, OSError):
            return  # porta 80 fechada: nada servido em texto claro
        finally:
            time.sleep(self.espera)
        if self.parar_se_erro_servidor(status):
            return
        location = next((v for k, v in headers.items() if k.lower() == "location"), "")
        if not (300 <= status < 400 and location.lower().startswith("https://")):
            self.achado("TRANSPORTE", "HTTP não redireciona para HTTPS", "media", "alta",
                        f"GET {alvo_http} -> {status}" + (f" Location: {location}" if location else ""),
                        "Redirecione toda requisição HTTP para HTTPS (301/308) e envie HSTS.", "CWE-319")

    def checar_cookies(self, headers):
        cookies = [v for k, v in headers.items() if k.lower() == "set-cookie"]
        if not cookies:
            self.achado("SESSAO", "Nenhum cookie observado em GET /", "baixa", "media",
                        "A página inicial não definiu cookies; autenticação pode ocorrer em outra rota.",
                        "Reexecute a checagem contra a rota de login em ambiente controlado.")
            return
        for cookie in cookies:
            nome = cookie.split("=", 1)[0].strip()
            base = re.sub(r"[^a-z0-9]", "", nome.lower())
            sensivel = any(t in base for t in ("session", "sess", "auth", "token", "sid", "login", "jwt"))
            minuscula = cookie.lower()
            gravidade = "media" if sensivel else "baixa"
            if "secure" not in minuscula and self.url.startswith("https://"):
                self.achado("SESSAO", f"Cookie sem flag Secure ({nome})", gravidade, "alta",
                            f"Set-Cookie: {cookie[:120]}",
                            "Envie apenas por HTTPS com flag Secure.", "CWE-614")
            if "httponly" not in minuscula and sensivel:
                self.achado("SESSAO", f"Cookie de sessão sem HttpOnly ({nome})", "media", "alta",
                            f"Set-Cookie: {cookie[:120]}",
                            "HttpOnly impede acesso do cookie a scripts em caso de XSS.", "CWE-1004")
            if "samesite" not in minuscula:
                self.achado("SESSAO", f"Cookie sem SameSite ({nome})", "baixa", "alta",
                            f"Set-Cookie: {cookie[:120]}",
                            "Defina SameSite=Lax/Strict conforme o fluxo; None exige Secure.", "CWE-1275")
            elif "samesite=none" in minuscula and "secure" not in minuscula:
                self.achado("SESSAO", f"SameSite=None sem Secure ({nome})", "media", "alta",
                            f"Set-Cookie: {cookie[:120]}",
                            "Browsers modernos rejeitam a combinação; corrija as flags.", "CWE-1275")

    def checar_cors(self):
        origem_sintetica = "https://origem-sintetica.invalid"
        status, headers, _ = self.requisitar("/", {"Origin": origem_sintetica})
        if self.parar_se_erro_servidor(status):
            return
        minusculas = {k.lower(): v for k, v in headers.items()}
        acao = minusculas.get("access-control-allow-origin", "")
        credenciais = minusculas.get("access-control-allow-credentials", "").lower() == "true"
        if acao == "*" and credenciais:
            self.achado("CORS", "CORS: qualquer origem com credenciais", "alta", "alta",
                        "Access-Control-Allow-Origin: * junto de Allow-Credentials: true.",
                        "Restrinja a origens conhecidas; '*' com credenciais não deve existir.", "CWE-942")
        elif acao == "*":
            self.achado("CORS", "CORS: qualquer origem autorizada", "baixa", "alta",
                        "Access-Control-Allow-Origin: * (sem credenciais).",
                        "Aceitável para conteúdo público; verifique se recursos sensíveis não usam '*'.", "CWE-942")
        elif acao == origem_sintetica:
            gravidade = "alta" if credenciais else "media"
            self.achado("CORS", "CORS reflete origem arbitrária", gravidade, "alta",
                        f"Origem sintética {origem_sintetica} foi refletida como permitida"
                        + (" com credenciais." if credenciais else "."),
                        "Use permitlist de origens; reflexão de Origin é controlável pelo atacante.", "CWE-942")

    def checar_erro_404(self):
        caminho = f"/caminho-inexistente-{random.randint(100000, 999999)}"
        status, headers, corpo = self.requisitar(caminho)
        if self.parar_se_erro_servidor(status):
            return
        if PADRAO_ERRO.search(corpo):
            self.achado("EXPOSICAO", "Página de erro vaza detalhes internos", "media", "media",
                        f"GET {caminho} retornou stack trace/detalhes internos.",
                        "Retorne erro genérico ao cliente; registre detalhes apenas em log interno.", "CWE-209")

    def checar_metodos(self):
        try:
            status, headers, _ = self.requisitar("/", metodo="OPTIONS")
        except Exception:
            return
        minusculas = {k.lower(): v for k, v in headers.items()}
        permitir = minusculas.get("allow", "")
        if not permitir:
            return
        metodos = {m.strip().upper() for m in permitir.split(",")}
        if "TRACE" in metodos:
            self.achado("SESSAO", "Método TRACE habilitado", "media", "alta",
                        f"Allow: {permitir}",
                        "Desabilite TRACE (Cross-Site Tracing).", "CWE-16")
        inesperados = metodos - {"GET", "HEAD", "OPTIONS", "POST"}
        if inesperados:
            self.achado("EXPOSICAO", f"Métodos não usuais expostos ({', '.join(sorted(inesperados))})",
                        "baixa", "media",
                        f"Allow: {permitir}",
                        "Confirme se são necessários; remova métodos não usados na borda/aplicação.", "CWE-16")

    ROTAS_SENSITIVEIS = (
        "/.git/config", "/.git/HEAD", "/.env", "/.svn/entries", "/.DS_Store", "/phpinfo.php",
        "/server-status", "/actuator", "/actuator/env", "/swagger-ui/index.html", "/api-docs",
        "/v2/api-docs", "/admin", "/backup.zip", "/db.sql", "/robots.txt", "/metrics",
        "/debug/pprof/", "/.well-known/security.txt",
    )

    def _exposicao_em_rota(self, caminho, status, corpo):
        minusculas = corpo.lower()
        if caminho == "/.git/config" and "[core]" in minusculas:
            return ("Repositório Git exposto (.git/config)",
                    "O conteúdo do .git ficou acessível sem autenticação.", "alta")
        if caminho == "/.git/HEAD" and corpo.startswith("ref: refs/"):
            return ("Repositório Git exposto (.git/HEAD)",
                    "O diretório .git está sendo servido; o código-fonte pode ser reconstruído.", "alta")
        if caminho == "/.DS_Store" and corpo.startswith("\x00\x00\x00\x01Bud1"):
            return ("Arquivo .DS_Store exposto",
                    "Revela nomes de arquivos e pastas do servidor.", "baixa")
        if caminho == "/metrics" and re.search(r"(?m)^# (?:HELP|TYPE) ", corpo):
            return ("Métricas Prometheus expostas",
                    "/metrics público revela internos (rotas, versões, filas).", "media")
        if caminho == "/debug/pprof/" and "profile" in minusculas and "goroutine" in minusculas:
            return ("Go pprof exposto",
                    "Endpoints de profiling permitem extrair memória e consumir CPU.", "alta")
        if caminho == "/.env" and re.search(
                r"(?mi)^\s*(?:export\s+)?(?:password|secret|api[_-]?key|token|db[_-]?pass)\s*=", corpo):
            return ("Arquivo .env exposto",
                    "Variáveis de ambiente/credenciais servidas sem autenticação.", "alta")
        if caminho == "/phpinfo.php" and "phpinfo" in minusculas:
            return ("phpinfo() exposto",
                    "Página phpinfo() acessível revela configuração e caminhos internos.", "media")
        if caminho == "/server-status" and ("apache status" in minusculas or "server status" in minusculas):
            return ("Apache server-status exposto", "Página de status do Apache acessível.", "media")
        if caminho.startswith("/actuator") and ('"_links"' in corpo or "exposures" in minusculas):
            return ("Spring Boot Actuator exposto",
                    "Endpoints de actuator podem revelar variáveis de ambiente e internos.", "media")
        if caminho in ("/swagger-ui/index.html", "/api-docs", "/v2/api-docs") and (
                "swagger" in minusculas or "openapi" in minusculas):
            return ("Documentação de API exposta", "Swagger/OpenAPI acessível em produção.", "baixa")
        if caminho == "/robots.txt" and "user-agent:" in minusculas:
            return ("robots.txt exposto", "Informativo: mapa de rotas público.", "baixa")
        if caminho in ("/backup.zip", "/db.sql") and status == 200 and corpo:
            return ("Possível backup/dump exposto",
                    f"{caminho} retornou conteúdo ({len(corpo)} bytes).", "alta")
        if caminho == "/admin" and status == 200:
            return ("Rota administrativa acessível",
                    "/admin respondeu 200; confirme autenticação e autorização.", "baixa")
        return None

    def checar_rotas_sensiveis(self):
        for caminho in self.ROTAS_SENSITIVEIS:
            status, _, corpo = self.requisitar(caminho, seguir_redirect=False)
            if self.parar_se_erro_servidor(status):
                return
            if caminho == "/.well-known/security.txt":
                if status != 200 or "contact:" not in corpo.lower():
                    self.achado("EXPOSICAO", "security.txt ausente", "baixa", "media",
                                "Sem /.well-known/security.txt, pesquisadores não têm canal para reportar falhas.",
                                "Publique security.txt (RFC 9116) com Contact e Expires.", "")
                continue
            if not (200 <= status < 400):
                continue
            exposicao = self._exposicao_em_rota(caminho, status, corpo)
            if exposicao:
                titulo, detalhe, severidade = exposicao
                self.achado("EXPOSICAO", titulo, severidade, "media", detalhe,
                            "Restrinja acesso, remova artefatos sensíveis e desative endpoints de diagnóstico em produção.",
                            "CWE-200")

    ROTAS_REDIRECT = ("/logout", "/sair", "/redirect", "/login")
    PARAMETROS_REDIRECT = ("url", "next")

    def checar_open_redirect(self):
        origem = "https://origem-sintetica.invalid"
        for rota in self.ROTAS_REDIRECT:
            for parametro in self.PARAMETROS_REDIRECT:
                caminho = f"{rota}?{parametro}={origem}"
                status, headers, _ = self.requisitar(caminho, seguir_redirect=False)
                if self.parar_se_erro_servidor(status):
                    return
                if not (300 <= status < 400):
                    continue
                location = next((v for k, v in headers.items() if k.lower() == "location"), "")
                if "origem-sintetica.invalid" in location:
                    self.achado("REDIRECIONAMENTO", "Redirecionamento aberto", "alta", "alta",
                                f"GET {caminho} -> Location: {location}",
                                "Valide destinos contra permitlist; não reflita parâmetro de URL.", "CWE-601")

    def checar_tls(self):
        host = urllib.parse.urlparse(self.url).hostname
        porta = urllib.parse.urlparse(self.url).port or 443
        contexto = ssl.create_default_context()
        try:
            with socket.create_connection((host, porta), timeout=self.timeout) as bruto:
                with contexto.wrap_socket(bruto, server_hostname=host) as tls:
                    protocolo = tls.version()
                    cert = tls.getpeercert()
        except ssl.SSLCertVerificationError as e:
            self.achado("TLS", "Certificado inválido ou não confiável", "alta", "alta",
                        f"Verificação falhou: {e.verify_message if hasattr(e, 'verify_message') else str(e)}",
                        "Emita/instale certificado válido de CA confiável.", "CWE-295")
            return
        except (OSError, ssl.SSLError) as e:
            self.achado("TLS", "Falha ao negociar TLS", "media", "media",
                        f"{e}",
                        "Verifique cadeia, protocolos e compatibilidade com clientes esperados.", "CWE-326")
            return
        agora = datetime.datetime.now(datetime.timezone.utc)
        valido_de = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
        valido_ate = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
        if agora > valido_ate:
            self.achado("TLS", "Certificado expirado", "alta", "alta",
                        f"Válido até {cert['notAfter']}.",
                        "Renove o certificado imediatamente.", "CWE-298")
        elif (valido_ate - agora).days < 30:
            self.achado("TLS", "Certificado expira em menos de 30 dias", "media", "alta",
                        f"Válido até {cert['notAfter']}.",
                        "Programe renovação automática.", "CWE-298")
        if protocolo and protocolo in ("TLSv1", "TLSv1.1"):
            self.achado("TLS", f"Protocolo legado em uso ({protocolo})", "alta", "alta",
                        f"Negociado: {protocolo}.",
                        "Desabilite TLS < 1.2 no servidor.", "CWE-327")

    def executar(self):
        resultado_headers = self.checar_headers()
        if self.interrompido:
            return
        minusculas, headers = resultado_headers
        self.checar_cookies(headers)
        if self.interrompido:
            return
        self.checar_cors()
        if self.interrompido:
            return
        self.checar_erro_404()
        if self.interrompido:
            return
        self.checar_metodos()
        if self.interrompido:
            return
        if not self.pular_rotas:
            self.checar_rotas_sensiveis()
        if self.interrompido:
            return
        if not self.pular_open_redirect:
            self.checar_open_redirect()
        if self.interrompido:
            return
        if self.url.startswith("https://"):
            self.checar_tls()
            if self.interrompido:
                return
            self.checar_redirect_https()

def cor(texto, codigo, ativo):
    return f"\033[{codigo}m{texto}\033[0m" if ativo else texto

def imprimir(bateria, ativo_cor):
    mapa_cor = {"alta": "31", "media": "33", "baixa": "36"}
    print("Bateria HTTP de segurança — resultados")
    print(f"Alvo declarado como autorizado: {bateria.url}")
    print(f"Requisições executadas: {bateria.requisicoes} (GET/OPTIONS, não destrutivas)")
    if bateria.interrompido:
        print(f"INTERRUPÇÃO: {bateria.interrompido}")
    print()
    if not bateria.achados:
        print("Nenhum achado nesta checagem superficial — não equivale a sistema seguro.")
        return
    atual = None
    for a in sorted(bateria.achados,
                    key=lambda x: (-SEVERIDADES[x["severidade"]], -CONFIANCAS[x["confianca"]])):
        if a["severidade"] != atual:
            atual = a["severidade"]
            print(cor(f"== Severidade {atual.upper()} ==", mapa_cor[atual], ativo_cor))
        print(f"[{a['categoria']}] {a['titulo']} (confiança: {a['confianca']})  {a['cwe']}")
        print(f"  detalhe: {a['detalhe']}")
        print(f"  ação: {a['acao']}")
        print()

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Checagens HTTP não destrutivas em ambiente controlado e autorizado.",
    )
    parser.add_argument("--url", required=True, help="URL base do ambiente (ex.: http://localhost:3000)")
    parser.add_argument("--autorizado", action="store_true",
                        help="declara que o alvo é ambiente controlado e autorizado para teste")
    parser.add_argument("--forcar-externo", action="store_true",
                        help="permite host não local após confirmação explícita de autorização")
    parser.add_argument("--espera", type=float, default=0.5, help="segundos entre requisições (padrão: 0.5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="timeout por requisição em segundos")
    parser.add_argument("--user-agent", default="bateria-vulnerabilidades/1.0 (ambiente controlado)")
    parser.add_argument("--json", help="grava relatório em JSON")
    parser.add_argument("--sem-cor", action="store_true")
    parser.add_argument("--pular-rotas-sensiveis", action="store_true",
                        help="não sonda rotas comuns de arquivos/endpoints expostos")
    parser.add_argument("--pular-open-redirect", action="store_true",
                        help="não testa redirecionamento aberto nas rotas comuns")
    args = parser.parse_args(argv)

    if not args.url.startswith(("http://", "https://")):
        sys.exit("erro: --url deve começar com http:// ou https://")
    if not args.autorizado:
        sys.exit("recusa: checagens HTTP exigem --autorizado declarando ambiente controlado e permissão explícita.\n"
                 "Sem autorização, use apenas a bateria estática (verificacao_estatica.py).")

    host = urllib.parse.urlparse(args.url).hostname
    if host and not host_eh_local(host) and not args.forcar_externo:
        sys.exit(f"recusa: {host} não parece ambiente local/staging.\n"
                 "Para alvos externos, confirme a autorização e reexecute com --forcar-externo.\n"
                 "Produção e sistemas de terceiros exigem escopo e permissão formais.")

    bateria = Bateria(args.url, args.espera, args.timeout, args.user_agent,
                      pular_rotas=args.pular_rotas_sensiveis,
                      pular_open_redirect=args.pular_open_redirect)
    try:
        bateria.executar()
    except KeyboardInterrupt:
        print("\ninterrupção manual — resultados parciais serão reportados")
    except (urllib.error.URLError, OSError) as e:
        print(f"erro de conexão: {e}\nbateria interrompida; verifique se o ambiente está acessível")
        sys.exit(2)

    imprimir(bateria, sys.stdout.isatty() and not args.sem_cor)

    if args.json:
        por_severidade = {"alta": 0, "media": 0, "baixa": 0}
        for a in bateria.achados:
            por_severidade[a["severidade"]] += 1
        relatorio = dict(
            ferramenta="verificacao_http",
            versao="1.1",
            gerado_em=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            alvo=args.url,
            requisicoes=bateria.requisicoes,
            interrompido=bateria.interrompido,
            resumo=dict(total=len(bateria.achados), por_severidade=por_severidade),
            achados=bateria.achados,
        )
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(relatorio, f, ensure_ascii=False, indent=2)
        print(f"relatório JSON gravado em: {args.json}")

    if any(a["severidade"] == "alta" for a in bateria.achados):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
