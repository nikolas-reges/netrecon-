# ⬡ NetRecon — Network Vulnerability Scanner

Ferramenta de reconhecimento e análise de vulnerabilidades de rede.




---

## 📁 Estrutura

```
vuln-scanner/
├── app.py           ← Backend Flask + engine de scan
├── requirements.txt
└── templates/
    └── index.html   ← Interface dark mode estilo terminal
```

---

## ⚙️ Como rodar

```bash
# 1. Ambiente virtual
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS

# 2. Dependências
pip install flask

# 3. Rodar
python app.py
```

Acesse: **http://127.0.0.1:5000**

---

## 🔍 O que o scanner faz

- **Port Scanning** paralelo com ThreadPoolExecutor (até 50 threads)
- **Banner Grabbing** — captura resposta inicial do serviço
- **CVE Lookup** — cruza porta/serviço com base de vulnerabilidades conhecidas
- **Risk Score** — calcula pontuação de risco (0-100) baseada nas descobertas
- **Relatório visual** — exibe tudo em interface estilo terminal/pentest

## 🧰 Tecnologias

Python · Flask · Socket · Threading · Chart-free UI

---

## 📌 Alvo de teste público (legal)

Quer testar sem ter servidor próprio? Use o alvo oficial do Nmap:

```
scanme.nmap.org
```

Esse host existe especificamente para testes de port scanning.
