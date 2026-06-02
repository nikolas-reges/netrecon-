NetRecon - Network Vulnerability Scanner

NetRecon é um laboratório de cibersegurança desenvolvido em Python e Flask para reconhecimento de rede, identificação de serviços e análise básica de exposição de sistemas.

O projeto evoluiu de um scanner baseado em sockets para uma solução que utiliza o motor real do Nmap para identificar serviços, versões e banners de aplicações encontradas durante a varredura.

Projeto educacional e de portfólio. Utilize apenas em ambientes próprios ou com autorização explícita.

Funcionalidades
Interface web desenvolvida com Flask
Descoberta de portas abertas
Identificação de serviços utilizando Nmap (-sV)
Captura de versões e banners dos serviços
Análise básica de risco
Scan paralelo utilizando ThreadPoolExecutor
Monitoramento de progresso em tempo real
Geração de score de risco (0–100)
Tecnologias Utilizadas
Python
Flask
Nmap
python-nmap
HTML
CSS
ThreadPoolExecutor
Estrutura do Projeto
netrecon/
│
├── app.py
├── requirements.txt
└── templates/
    └── index.html
Instalação
1. Criar ambiente virtual
python -m venv venv
2. Ativar ambiente virtual

Windows:

venv\Scripts\activate

Linux/macOS:

source venv/bin/activate
3. Instalar dependências
pip install -r requirements.txt
4. Instalar Nmap

Baixe e instale:

Nmap
Npcap

Durante a instalação do Npcap mantenha as opções padrão recomendadas.

Executando
python app.py

A aplicação ficará disponível em:

http://127.0.0.1:5001
Aprendizados

Durante o desenvolvimento deste projeto foram trabalhados conceitos de:

Redes TCP/IP
Port Scanning
Service Enumeration
Banner Grabbing
Flask
APIs REST
Multithreading
Troubleshooting
Segurança Ofensiva
Avaliação de Risco
Aviso Legal

Esta ferramenta foi desenvolvida exclusivamente para fins educacionais e de laboratório.

Nunca realize varreduras em sistemas ou redes sem autorização prévia.
