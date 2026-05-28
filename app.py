"""
NetRecon — Network Vulnerability Scanner
Pentest Portfolio Project
Autor: Nikolas Reges
USO: Somente em redes/sistemas próprios ou com autorização explícita.
"""

from flask import Flask, render_template, jsonify, request
import socket
import threading
import json
import time
import platform
import subprocess
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)

# ─────────────────────────────────────────────
# BASE DE VULNERABILIDADES CONHECIDAS POR SERVIÇO/PORTA
# (Simulação didática — em produção usaria NVD/CVE APIs)
# ─────────────────────────────────────────────
VULN_DB = {
    21: {
        "service": "FTP",
        "vulns": [
            {"id": "CVE-2011-2523", "severity": "CRÍTICO", "desc": "vsftpd 2.3.4 backdoor — permite execução remota de código via smiley ':)' no usuário.", "cvss": 10.0},
            {"id": "CVE-2010-4221", "severity": "ALTO",    "desc": "ProFTPD heap overflow — possibilita RCE via comandos TELNET IAC.", "cvss": 7.5},
            {"id": "FTP-ANON",      "severity": "MÉDIO",   "desc": "Login anônimo pode estar habilitado — verificar acesso sem credenciais.", "cvss": 5.0},
        ]
    },
    22: {
        "service": "SSH",
        "vulns": [
            {"id": "CVE-2018-15473", "severity": "MÉDIO",  "desc": "OpenSSH User Enumeration — permite descoberta de usuários válidos via timing attack.", "cvss": 5.3},
            {"id": "CVE-2016-0777",  "severity": "MÉDIO",  "desc": "OpenSSH roaming — vazamento de chave privada via feature de roaming.", "cvss": 6.4},
            {"id": "SSH-WEAK-ALGO",  "severity": "BAIXO",  "desc": "Verificar se algoritmos fracos (MD5, SHA1) estão habilitados.", "cvss": 3.1},
        ]
    },
    23: {
        "service": "Telnet",
        "vulns": [
            {"id": "TELNET-PLAIN",   "severity": "CRÍTICO", "desc": "Telnet transmite dados em texto puro — credenciais expostas na rede.", "cvss": 9.8},
            {"id": "CVE-2011-4862",  "severity": "CRÍTICO", "desc": "Buffer overflow no telnetd — RCE sem autenticação.", "cvss": 10.0},
        ]
    },
    25: {
        "service": "SMTP",
        "vulns": [
            {"id": "SMTP-RELAY",     "severity": "ALTO",   "desc": "Open relay pode permitir envio de spam e phishing pelo servidor.", "cvss": 7.5},
            {"id": "CVE-2020-7247",  "severity": "CRÍTICO", "desc": "OpenSMTPD RCE — execução remota via endereço malformado.", "cvss": 9.8},
        ]
    },
    53: {
        "service": "DNS",
        "vulns": [
            {"id": "DNS-ZONE-XFER",  "severity": "ALTO",   "desc": "Zone Transfer aberta — expõe toda estrutura de DNS interna.", "cvss": 7.5},
            {"id": "CVE-2020-1350",  "severity": "CRÍTICO", "desc": "SIGRed — Windows DNS RCE via pacote DNS malformado.", "cvss": 10.0},
        ]
    },
    80: {
        "service": "HTTP",
        "vulns": [
            {"id": "HTTP-PLAIN",     "severity": "MÉDIO",  "desc": "Serviço HTTP sem TLS — tráfego em texto puro, sujeito a MITM.", "cvss": 5.9},
            {"id": "CVE-2021-41773", "severity": "CRÍTICO", "desc": "Apache Path Traversal — acesso a arquivos fora do webroot.", "cvss": 7.5},
            {"id": "CVE-2017-5638",  "severity": "CRÍTICO", "desc": "Apache Struts2 RCE — execução de código via Content-Type header.", "cvss": 10.0},
        ]
    },
    110: {
        "service": "POP3",
        "vulns": [
            {"id": "POP3-PLAIN",     "severity": "ALTO",   "desc": "POP3 sem TLS — credenciais de e-mail em texto puro.", "cvss": 7.4},
        ]
    },
    135: {
        "service": "RPC/MSRPC",
        "vulns": [
            {"id": "CVE-2003-0352",  "severity": "CRÍTICO", "desc": "MS03-026 — Blaster worm. Buffer overflow no RPC DCOM.", "cvss": 10.0},
        ]
    },
    139: {
        "service": "NetBIOS",
        "vulns": [
            {"id": "CVE-2017-0144",  "severity": "CRÍTICO", "desc": "EternalBlue — SMB RCE usado pelo WannaCry ransomware.", "cvss": 9.8},
            {"id": "NETBIOS-INFO",   "severity": "MÉDIO",   "desc": "NetBIOS pode expor informações de hostname, domínio e usuários.", "cvss": 5.0},
        ]
    },
    143: {
        "service": "IMAP",
        "vulns": [
            {"id": "IMAP-PLAIN",     "severity": "ALTO",   "desc": "IMAP sem TLS — e-mails e credenciais trafegando em texto puro.", "cvss": 7.4},
        ]
    },
    443: {
        "service": "HTTPS",
        "vulns": [
            {"id": "CVE-2014-0160",  "severity": "CRÍTICO", "desc": "Heartbleed — vazamento de memória no OpenSSL, expõe chaves privadas.", "cvss": 7.5},
            {"id": "CVE-2014-3566",  "severity": "ALTO",    "desc": "POODLE — downgrade SSLv3 permite decriptação de tráfego.", "cvss": 3.4},
        ]
    },
    445: {
        "service": "SMB",
        "vulns": [
            {"id": "CVE-2017-0144",  "severity": "CRÍTICO", "desc": "EternalBlue — SMBv1 RCE. Explorado pelo WannaCry e NotPetya.", "cvss": 9.8},
            {"id": "CVE-2020-0796",  "severity": "CRÍTICO", "desc": "SMBGhost — SMBv3 RCE sem autenticação no Windows 10.", "cvss": 10.0},
        ]
    },
    1433: {
        "service": "MSSQL",
        "vulns": [
            {"id": "MSSQL-SA",       "severity": "CRÍTICO", "desc": "Conta SA com senha padrão/fraca — acesso total ao banco.", "cvss": 9.8},
            {"id": "CVE-2020-0618",  "severity": "CRÍTICO", "desc": "SQL Server RCE via SQL Server Reporting Services.", "cvss": 8.8},
        ]
    },
    3306: {
        "service": "MySQL",
        "vulns": [
            {"id": "MYSQL-ROOT",     "severity": "CRÍTICO", "desc": "MySQL root acessível remotamente — verificar autenticação.", "cvss": 9.8},
            {"id": "CVE-2012-2122",  "severity": "CRÍTICO", "desc": "Bypass de autenticação MySQL via timing attack.", "cvss": 5.1},
        ]
    },
    3389: {
        "service": "RDP",
        "vulns": [
            {"id": "CVE-2019-0708",  "severity": "CRÍTICO", "desc": "BlueKeep — RDP RCE sem autenticação. Wormable.", "cvss": 9.8},
            {"id": "CVE-2019-1182",  "severity": "CRÍTICO", "desc": "DejaBlue — RDP RCE similar ao BlueKeep.", "cvss": 9.8},
            {"id": "RDP-BRUTE",      "severity": "ALTO",    "desc": "RDP exposto publicamente — alvo comum de ataques de força bruta.", "cvss": 7.5},
        ]
    },
    5432: {
        "service": "PostgreSQL",
        "vulns": [
            {"id": "PGSQL-TRUST",    "severity": "ALTO",    "desc": "Autenticação trust pode permitir acesso sem senha.", "cvss": 8.1},
        ]
    },
    5900: {
        "service": "VNC",
        "vulns": [
            {"id": "VNC-NOAUTH",     "severity": "CRÍTICO", "desc": "VNC sem autenticação — acesso remoto ao desktop sem senha.", "cvss": 9.8},
            {"id": "CVE-2019-15694", "severity": "CRÍTICO", "desc": "LibVNCServer heap overflow — RCE via conexão VNC.", "cvss": 9.8},
        ]
    },
    6379: {
        "service": "Redis",
        "vulns": [
            {"id": "REDIS-NOAUTH",   "severity": "CRÍTICO", "desc": "Redis sem autenticação exposto — leitura/escrita livre de dados.", "cvss": 9.8},
            {"id": "CVE-2022-0543",  "severity": "CRÍTICO", "desc": "Redis Lua sandbox escape — RCE via eval().", "cvss": 10.0},
        ]
    },
    8080: {
        "service": "HTTP-ALT",
        "vulns": [
            {"id": "HTTP-ALT-PLAIN", "severity": "MÉDIO",  "desc": "Serviço HTTP alternativo sem TLS.", "cvss": 5.3},
            {"id": "JENKINS-RCE",    "severity": "CRÍTICO", "desc": "Jenkins pode estar exposto sem autenticação — Script Console permite RCE.", "cvss": 9.8},
        ]
    },
    27017: {
        "service": "MongoDB",
        "vulns": [
            {"id": "MONGO-NOAUTH",   "severity": "CRÍTICO", "desc": "MongoDB sem autenticação — banco de dados totalmente exposto.", "cvss": 9.8},
        ]
    },
}

# Portas comuns pra escanear por padrão
DEFAULT_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139,
    143, 443, 445, 1433, 3306, 3389, 5432,
    5900, 6379, 8080, 8443, 27017
]

# Estado global dos scans em andamento
scan_results = {}
scan_status  = {}


def scan_port(host: str, port: int, timeout: float = 1.0) -> dict:
    """Tenta conectar numa porta e retorna resultado."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()

        if result == 0:
            # Porta aberta — pega banner se possível
            banner = grab_banner(host, port)
            vuln_info = VULN_DB.get(port, {})
            return {
                "port":    port,
                "status":  "ABERTA",
                "service": vuln_info.get("service", "Desconhecido"),
                "banner":  banner,
                "vulns":   vuln_info.get("vulns", []),
            }
        else:
            return {"port": port, "status": "FECHADA", "service": "", "banner": "", "vulns": []}
    except Exception:
        return {"port": port, "status": "FILTRADA", "service": "", "banner": "", "vulns": []}


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """Tenta capturar o banner do serviço."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        # Para HTTP manda um HEAD request
        if port in (80, 8080, 8443):
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        elif port == 443:
            sock.close()
            return "SSL/TLS — banner requer handshake"

        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        # Pega só a primeira linha
        return banner.split("\n")[0][:120] if banner else ""
    except Exception:
        return ""


def resolve_host(host: str) -> dict:
    """Resolve hostname para IP e coleta informações básicas."""
    info = {"host": host, "ip": "", "hostname": "", "os_guess": "Desconhecido"}
    try:
        ip = socket.gethostbyname(host)
        info["ip"] = ip
        try:
            info["hostname"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            info["hostname"] = host
    except Exception:
        info["ip"] = "Não resolvido"
    return info


def ping_host(host: str) -> bool:
    """Verifica se o host responde a ping."""
    try:
        param = "-n" if platform.system().lower() == "windows" else "-c"
        result = subprocess.run(
            ["ping", param, "1", "-W", "1", host],
            capture_output=True, timeout=3
        )
        return result.returncode == 0
    except Exception:
        return False


def run_scan(scan_id: str, host: str, ports: list):
    """Executa o scan completo em thread separada."""
    scan_status[scan_id] = {"status": "running", "progress": 0, "total": len(ports)}

    # Resolve o host
    host_info = resolve_host(host)
    if host_info["ip"] == "Não resolvido":
        scan_status[scan_id] = {"status": "error", "message": f"Não foi possível resolver o host: {host}"}
        return

    # Ping
    is_alive = ping_host(host_info["ip"])

    open_ports   = []
    closed_ports = []
    total_vulns  = 0
    critical_count = 0
    scanned = 0

    # Scan paralelo com ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host_info["ip"], port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            scanned += 1
            scan_status[scan_id]["progress"] = int((scanned / len(ports)) * 100)

            if result["status"] == "ABERTA":
                open_ports.append(result)
                total_vulns += len(result["vulns"])
                for v in result["vulns"]:
                    if v["severity"] == "CRÍTICO":
                        critical_count += 1
            else:
                closed_ports.append(result)

    # Ordena portas abertas
    open_ports.sort(key=lambda x: x["port"])

    # Calcula risk score (0-100)
    risk_score = min(100, (critical_count * 20) + (total_vulns * 5) + (len(open_ports) * 2))
    if risk_score >= 75:
        risk_level = "CRÍTICO"
    elif risk_score >= 50:
        risk_level = "ALTO"
    elif risk_score >= 25:
        risk_level = "MÉDIO"
    else:
        risk_level = "BAIXO"

    scan_results[scan_id] = {
        "scan_id":       scan_id,
        "timestamp":     datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "host_info":     host_info,
        "is_alive":      is_alive,
        "open_ports":    open_ports,
        "total_open":    len(open_ports),
        "total_scanned": len(ports),
        "total_vulns":   total_vulns,
        "critical_count": critical_count,
        "risk_score":    risk_score,
        "risk_level":    risk_level,
    }

    scan_status[scan_id] = {"status": "done", "progress": 100, "total": len(ports)}


# ─────────────────────────────────────────────
# ROTAS FLASK
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    """Inicia um novo scan."""
    data = request.get_json()
    host = data.get("host", "").strip()
    port_range = data.get("port_range", "default")

    if not host:
        return jsonify({"error": "Host inválido"}), 400

    # Define portas a escanear
    if port_range == "default":
        ports = DEFAULT_PORTS
    elif port_range == "top100":
        ports = DEFAULT_PORTS + [
            26, 69, 79, 88, 111, 119, 161, 162, 194, 389,
            427, 465, 500, 514, 515, 543, 544, 548, 554, 587,
            631, 636, 646, 873, 990, 993, 995, 1080, 1194, 1352,
            1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
            2121, 3000, 3128, 3268, 3269, 4443, 4848, 5000, 5001,
            5060, 5061, 5985, 5986, 6000, 6001, 6443, 7001, 7002,
            7070, 7080, 8000, 8008, 8009, 8180, 8443, 8888, 9000,
            9090, 9200, 9300, 9418, 9999, 10000, 11211, 27018,
        ]
    else:
        ports = DEFAULT_PORTS

    scan_id = f"scan_{int(time.time())}"
    thread = threading.Thread(target=run_scan, args=(scan_id, host, ports), daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/status")
def scan_status_endpoint(scan_id):
    status = scan_status.get(scan_id, {"status": "not_found"})
    return jsonify(status)


@app.route("/api/scan/<scan_id>/result")
def scan_result(scan_id):
    result = scan_results.get(scan_id)
    if not result:
        return jsonify({"error": "Resultado não encontrado"}), 404
    return jsonify(result)


if __name__ == "__main__":
    print("=" * 60)
    print("  NetRecon — Network Vulnerability Scanner")
    print("  ⚠  USE APENAS EM SISTEMAS PRÓPRIOS OU AUTORIZADOS")
    print("  Acesse: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
