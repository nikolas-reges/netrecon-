# 🔍 NetRecon

### Network Vulnerability Scanner powered by Flask + Nmap

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Flask-Web%20Framework-black)
![Nmap](https://img.shields.io/badge/Nmap-Service%20Enumeration-green)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## 📖 About The Project

NetRecon is a cybersecurity laboratory project developed for network reconnaissance, service enumeration and basic exposure assessment.

The project started as a socket-based scanner and evolved into a solution powered by the real Nmap engine, enabling service identification, version detection and banner collection.

> ⚠️ Educational and portfolio project. Use only on systems and networks you own or are authorized to assess.

---

## 🚀 Features

✅ Open Port Discovery

✅ Service Enumeration using Nmap (`-sV`)

✅ Software Version Detection

✅ Banner Collection

✅ Basic Risk Assessment

✅ Parallel Scanning with ThreadPoolExecutor

✅ Flask Web Dashboard

✅ Real-Time Progress Tracking

---

## 🛠️ Technologies

* Python
* Flask
* Nmap
* python-nmap
* HTML
* CSS
* Multithreading

---

## 📂 Project Structure

```text
netrecon/
├── app.py
├── index.html
├── requisitos.txt
├── modelos/
└── README.md
```

---

## ⚙️ Installation

### 1. Create a Virtual Environment

```bash
python -m venv venv
```

### 2. Activate the Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requisitos.txt
```

### 4. Install Nmap and Npcap

Download and install:

* Nmap
* Npcap

Keep the default recommended options during installation.

---

## ▶️ Running the Application

```bash
python app.py
```

Access the dashboard:

```text
http://127.0.0.1:5001
```

---

## 🎯 Concepts Applied

* TCP/IP
* Port Scanning
* Service Enumeration
* Banner Grabbing
* REST APIs
* Flask Development
* Multithreading
* Risk Assessment
* Troubleshooting
* Cybersecurity Fundamentals

---

## 📌 Roadmap

* [x] Socket-Based Port Scanner
* [x] Nmap Integration
* [x] Service Enumeration
* [ ] Report Exporting
* [ ] Advanced Dashboard
* [ ] CVE API Integration
* [ ] Historical Scan Storage

---

## ⚖️ Legal Disclaimer

This tool was developed exclusively for educational and research purposes.

Do not scan, probe or assess systems without prior authorization.

The author assumes no responsibility for misuse of this software.
