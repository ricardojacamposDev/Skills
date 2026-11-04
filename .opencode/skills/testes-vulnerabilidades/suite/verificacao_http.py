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

def host_eh_local(host):
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local") or host.endswith(".internal"):
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return False
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            return True
    return False

class Bateria:
    def __init__(self, url, espera, timeout, user_agent):
        self.url = url.rstrip("/")
        self.espera = espera
        self.timeout = timeout
        self.user_agent = user_agent
        self.achados = []
        self.requisicoes = 0
        self.interrompido = None

    def achado(self, categoria, titulo, severidade, confianca, detalhe, acao, cwe=""):
        self.achados.append(dict(
            categoria=categoria, id=None, titulo=titulo, severidade=severidade,
            confianca=confianca, cwe=cwe, local=self.url, detalhe=detalhe, acao=acao,
        ))

    def requisitar(self, caminho="/", headers=None, metodo="GET"):
        alvo = self.url + caminho
        pedido = urllib.request.Request(alvo, method=metodo, headers={"User-Agent": self.user_agent})
        for k, v in (headers or {}).items():
            pedido.add_header(k, v)
        self.requisicoes += 1
        try:
            with urllib.request.urlopen(pedido, timeout=self.timeout) as resposta:
                corpo = resposta.read(200_000).decode("utf-8", errors="replace")
                return resposta.status, dict(resposta.headers.items()), corpo
        except urllib.error.HTTPError as e:
            corpo = e.read(200_000).decode("utf-8", errors="replace")
            return e.code, dict(e.headers.items()), corpo
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

    def checar_tls(self):
        from urllib.parse import urlparse
        host = urlparse(self.url).hostname
        porta = urlparse(self.url).port or 443
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
        if self.url.startswith("https://"):
            self.checar_tls()

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

def main():
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
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        sys.exit("erro: --url deve começar com http:// ou https://")
    if not args.autorizado:
        sys.exit("recusa: checagens HTTP exigem --autorizado declarando ambiente controlado e permissão explícita.\n"
                 "Sem autorização, use apenas a bateria estática (verificacao_estatica.py).")

    from urllib.parse import urlparse
    host = urlparse(args.url).hostname
    if host and not host_eh_local(host) and not args.forcar_externo:
        sys.exit(f"recusa: {host} não parece ambiente local/staging.\n"
                 "Para alvos externos, confirme a autorização e reexecute com --forcar-externo.\n"
                 "Produção e sistemas de terceiros exigem escopo e permissão formais.")

    bateria = Bateria(args.url, args.espera, args.timeout, args.user_agent)
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
            versao="1.0",
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
