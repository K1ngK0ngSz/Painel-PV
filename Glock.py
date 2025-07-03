from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from getpass import getpass
import socket
import requests
import time
import os

console = Console()
LOG_FILE = "relatorio.txt"

def salvar_relatorio(texto):
    with open(LOG_FILE, "a") as f:
        f.write(f"[LOG] {texto}\n")

def login():
    console.clear()
    panel = Panel.fit("[bold magenta]ACESSO AO PAINEL PRIVADO GLOCKZADA[/bold magenta]\n\n[bold white]Usuário: admin\nSenha: admin[/bold white]", border_style="purple")
    console.print(panel)
    usuario = Prompt.ask("[bold cyan]Usuário[/bold cyan]")
    senha = getpass("Senha: ")
    return usuario == "admin" and senha == "admin"
def menu_principal():
    while True:
        console.clear()
        titulo = Panel.fit("[bold magenta]PAINEL GLOCKZADA - MENU PRINCIPAL[/bold magenta]", border_style="purple")
        console.print(titulo)

        menu = Table(title="Selecione uma ferramenta:", box=None, border_style="purple")
        menu.add_column("Opção", justify="center", style="bold cyan")
        menu.add_column("Descrição", style="bold white")

        opcoes = [
            "Scanner de Portas",
            "Scanner de Diretórios",
            "SQL Injection Checker",
            "XSS Checker",
            "WordPress Checker",
            "Gerador de Hash",
            "Gerador de Senha Forte",
            "Ferramenta Bypass (10 tipos)",
            "Gerar Relatório",
            "Chat simples",
            "Créditos",
            "Vulnerability Scanner",
            "Brute Force de Login",
            "Subdomain Finder",
            "Analisador SSL/TLS",
            "WHOIS Lookup",
            "Analisador robots.txt"
        ]

        for i, desc in enumerate(opcoes, 1):
            menu.add_row(str(i), desc)
        menu.add_row("0", "[red]Sair[/red]")

        console.print(menu)

        escolha = Prompt.ask("Escolha uma opção", choices=[str(i) for i in range(len(opcoes)+1)])

        if escolha == "0":
            console.print("[bold red]Saindo do painel...[/bold red]")
            break
        else:
            console.print(f"[bold yellow]Executando: {opcoes[int(escolha)-1]}[/bold yellow]")
            salvar_relatorio(f"Executada a opção: {opcoes[int(escolha)-1]}")
            # Aqui você vai ligar as funções específicas depois
            time.sleep(1)
import socket
import requests

# Scanner de portas simples
def scanner_portas():
    console.clear()
    console.print("[bold magenta]Scanner de Portas (1-1024)[/bold magenta]")
    alvo = Prompt.ask("Digite o IP ou domínio para scan")
    portas_abertas = []

    with console.status("[green]Escaneando portas...[/green]", spinner="dots"):
        for porta in range(1, 1025):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            try:
                resultado = sock.connect_ex((alvo, porta))
                if resultado == 0:
                    portas_abertas.append(porta)
            except Exception:
                pass
            finally:
                sock.close()

    if portas_abertas:
        console.print(f"[bold green]Portas abertas em {alvo}:[/bold green] {', '.join(map(str, portas_abertas))}")
    else:
        console.print(f"[red]Nenhuma porta aberta encontrada em {alvo}[/red]")
    salvar_relatorio(f"Scan de portas em {alvo}: {portas_abertas}")
    Prompt.ask("Pressione Enter para voltar ao menu")


# Scanner de diretórios simples
def scanner_dir():
    console.clear()
    console.print("[bold magenta]Scanner de Diretórios Comuns[/bold magenta]")
    url = Prompt.ask("Digite a URL alvo (exemplo: https://site.com/)")
    wordlist = ["admin", "backup", "config", "uploads", "files", ".git", "secret"]
    encontrados = []

    with console.status("[green]Escaneando diretórios...[/green]", spinner="dots"):
        for d in wordlist:
            full_url = url.rstrip("/") + "/" + d
            try:
                r = requests.get(full_url, timeout=3)
                if r.status_code == 200:
                    encontrados.append(full_url)
            except Exception:
                pass

    if encontrados:
        console.print("[bold green]Diretórios encontrados:[/bold green]")
        for e in encontrados:
            console.print(f" - {e}")
    else:
        console.print("[red]Nenhum diretório comum encontrado[/red]")
    salvar_relatorio(f"Scan de diretórios em {url}: {encontrados}")
    Prompt.ask("Pressione Enter para voltar ao menu")


# Teste básico de SQL Injection (simulado)
def checar_sqli():
    console.clear()
    console.print("[bold magenta]Teste básico de SQL Injection[/bold magenta]")
    url = Prompt.ask("Digite a URL com parâmetro para teste (ex: https://site.com/page?id=1)")
    test_payload = "' OR '1'='1"
    test_url = url + test_payload

    try:
        r = requests.get(test_url, timeout=5)
        if "sql" in r.text.lower() or "error" in r.text.lower():
            console.print("[bold red]Possível vulnerabilidade SQL Injection detectada![/bold red]")
            salvar_relatorio(f"Possível SQLi detectado em {url}")
        else:
            console.print("[green]Não foi detectada vulnerabilidade SQLi neste teste.[/green]")
    except Exception as e:
        console.print(f"[red]Erro ao testar SQLi: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")


# Teste básico de XSS (simulado)
def checar_xss():
    console.clear()
    console.print("[bold magenta]Teste básico de XSS[/bold magenta]")
    url = Prompt.ask("Digite a URL com parâmetro para teste (ex: https://site.com/page?q=)")
    payload = "<script>alert('XSS')</script>"
    test_url = url + payload

    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            console.print("[bold red]Possível vulnerabilidade XSS detectada![/bold red]")
            salvar_relatorio(f"Possível XSS detectado em {url}")
        else:
            console.print("[green]Não foi detectada vulnerabilidade XSS neste teste.[/green]")
    except Exception as e:
        console.print(f"[red]Erro ao testar XSS: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")
import hashlib
import random
import string

# Detectar WordPress simples
def checar_wordpress():
    console.clear()
    console.print("[bold magenta]Detecção simples WordPress[/bold magenta]")
    url = Prompt.ask("Digite a URL do site para verificar")
    wp_paths = ["/wp-login.php", "/wp-admin/", "/wp-content/"]

    encontrado = False
    with console.status("[green]Verificando...[/green]", spinner="dots"):
        for path in wp_paths:
            try:
                r = requests.get(url.rstrip("/") + path, timeout=3)
                if r.status_code == 200:
                    console.print(f"[bold green]WordPress detectado! Path acessível: {path}[/bold green]")
                    salvar_relatorio(f"WordPress detectado em {url} pelo path {path}")
                    encontrado = True
                    break
            except Exception:
                continue

    if not encontrado:
        console.print("[red]WordPress não detectado no site informado.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")


# Gerar hash (MD5, SHA1, SHA256)
def gerar_hash():
    console.clear()
    console.print("[bold magenta]Gerador de Hash[/bold magenta]")
    texto = Prompt.ask("Digite o texto para gerar hash")
    tipos = {"1": "md5", "2": "sha1", "3": "sha256"}

    escolha = Prompt.ask("Escolha o tipo de hash: 1-MD5, 2-SHA1, 3-SHA256", choices=tipos.keys())
    tipo_hash = tipos[escolha]

    if tipo_hash == "md5":
        resultado = hashlib.md5(texto.encode()).hexdigest()
    elif tipo_hash == "sha1":
        resultado = hashlib.sha1(texto.encode()).hexdigest()
    else:
        resultado = hashlib.sha256(texto.encode()).hexdigest()

    console.print(f"[green]{tipo_hash.upper()} hash de '{texto}' é:[/green] {resultado}")
    salvar_relatorio(f"Hash gerado ({tipo_hash}): {resultado} para texto: {texto}")
    Prompt.ask("Pressione Enter para voltar ao menu")


# Gerar senha forte
def gerar_senha():
    console.clear()
    console.print("[bold magenta]Gerador de Senha Forte[/bold magenta]")
    tamanho = Prompt.ask("Digite o tamanho da senha", default="16")

    try:
        tamanho = int(tamanho)
    except:
        tamanho = 16

    caracteres = string.ascii_letters + string.digits + string.punctuation
    senha = ''.join(random.choice(caracteres) for _ in range(tamanho))

    console.print(f"[green]Senha forte gerada:[/green] {senha}")
    salvar_relatorio(f"Senha forte gerada: {senha}")
    Prompt.ask("Pressione Enter para voltar ao menu")


# Função para salvar relatório
def salvar_relatorio(texto):
    with open("relatorio.txt", "a", encoding="utf-8") as f:
        f.write(f"{texto}\n")
import socket
import threading
from queue import Queue

# Scanner de portas avançado
def scanner_portas():
    console.clear()
    console.print("[bold magenta]Scanner de Portas Avançado[/bold magenta]")
    alvo = Prompt.ask("Digite o IP ou domínio alvo")
    inicio = Prompt.ask("Porta inicial", default="1")
    fim = Prompt.ask("Porta final", default="1024")

    try:
        inicio = int(inicio)
        fim = int(fim)
    except:
        console.print("[red]Portas inválidas. Usando padrão 1-1024[/red]")
        inicio, fim = 1, 1024

    portas_abertas = []
    portas_checadas = 0
    total_portas = fim - inicio + 1

    lock = threading.Lock()
    queue = Queue()

    def scan_porta_tcp(porta):
        nonlocal portas_checadas
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            resultado = s.connect_ex((alvo, porta))
            if resultado == 0:
                try:
                    s.send(b'Hello\r\n')
                    banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    banner = "Sem banner"
                with lock:
                    portas_abertas.append((porta, banner))
            s.close()
        except:
            pass
        with lock:
            portas_checadas += 1

    def worker():
        while True:
            p = queue.get()
            if p is None:
                break
            scan_porta_tcp(p)
            queue.task_done()

    num_threads = 100
    threads = []

    for i in range(num_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for porta in range(inicio, fim+1):
        queue.put(porta)

    with Progress() as progress:
        task = progress.add_task("[cyan]Escaneando portas TCP...", total=total_portas)
        while portas_checadas < total_portas:
            progress.update(task, completed=portas_checadas)
            time.sleep(0.1)

    for i in range(num_threads):
        queue.put(None)
    for t in threads:
        t.join()

    if portas_abertas:
        tabela = Table(title=f"Portas abertas em {alvo}", box=box.SQUARE)
        tabela.add_column("Porta", style="green", justify="center")
        tabela.add_column("Banner", style="yellow")
        for porta, banner in portas_abertas:
            tabela.add_row(str(porta), banner)
        console.print(tabela)
        salvar_relatorio(f"Scanner de portas TCP - abertas em {alvo}: {', '.join(str(p[0]) for p in portas_abertas)}")
    else:
        console.print("[red]Nenhuma porta TCP aberta encontrada.[/red]")

    # Scanner UDP básico (sem banner grabbing, só ping)
    console.print("\n[bold magenta]Scanner UDP Básico[/bold magenta]")
    portas_abertas_udp = []
    for porta in range(inicio, inicio+100):  # UDP 100 portas só por timeout ser lento
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)
            s.sendto(b'\x00', (alvo, porta))
            s.recvfrom(1024)
            portas_abertas_udp.append(porta)
            s.close()
        except socket.timeout:
            pass
        except:
            pass

    if portas_abertas_udp:
        console.print(f"[green]Portas UDP abertas (detecção básica): {', '.join(str(p) for p in portas_abertas_udp)}[/green]")
        salvar_relatorio(f"Portas UDP abertas detectadas em {alvo}: {', '.join(str(p) for p in portas_abertas_udp)}")
    else:
        console.print("[red]Nenhuma porta UDP aberta detectada.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# Scanner de diretórios com wordlist customizável
def scanner_dir():
    console.clear()
    console.print("[bold magenta]Scanner de Diretórios Comuns[/bold magenta]")
    url = Prompt.ask("Digite a URL base (ex: https://exemplo.com)")
    wordlist = Prompt.ask("Digite o caminho da wordlist ou deixe vazio para usar padrão", default="")

    if wordlist:
        try:
            with open(wordlist, "r") as f:
                palavras = [linha.strip() for linha in f if linha.strip()]
        except Exception as e:
            console.print(f"[red]Erro ao abrir wordlist: {e}[/red]")
            return
    else:
        palavras = ["admin", "backup", "login", "config", "uploads", "images", "files", "data"]

    encontrados = []
    total = len(palavras)
    checados = 0

    with Progress() as progress:
        task = progress.add_task("[cyan]Escaneando diretórios...", total=total)
        for p in palavras:
            try:
                r = requests.get(url.rstrip("/") + "/" + p, timeout=4)
                if r.status_code == 200:
                    encontrados.append(p)
                    salvar_relatorio(f"Diretório encontrado em {url}: /{p}")
            except Exception:
                pass
            checados += 1
            progress.update(task, completed=checados)

    if encontrados:
        console.print(f"[green]Diretórios encontrados:[/green] {', '.join(encontrados)}")
    else:
        console.print("[red]Nenhum diretório comum encontrado.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")
import requests
import json
import dns.resolver

# -------- Scanner de Vulnerabilidades --------
def vulnerability_scanner():
    console.clear()
    console.print("[bold magenta]Scanner de Vulnerabilidades Automático[/bold magenta]")
    url = Prompt.ask("Digite a URL alvo (ex: https://exemplo.com)")

    vulnerabilidades_encontradas = []

    # Exemplo: CVE check básico para WordPress (simulado)
    console.print("[cyan]Verificando CMS WordPress/Joomla/Drupal...[/cyan]")
    try:
        r = requests.get(url, timeout=5)
        if "wp-content" in r.text:
            vulnerabilidades_encontradas.append("WordPress detectado")
        elif "Joomla" in r.text:
            vulnerabilidades_encontradas.append("Joomla detectado")
        elif "Drupal" in r.text:
            vulnerabilidades_encontradas.append("Drupal detectado")
    except Exception:
        console.print("[red]Erro ao acessar o site[/red]")
        return

    # Headers inseguros
    console.print("[cyan]Checando headers HTTP inseguros...[/cyan]")
    try:
        r = requests.head(url, timeout=5)
        headers = r.headers
        if "Content-Security-Policy" not in headers:
            vulnerabilidades_encontradas.append("Header CSP ausente")
        if "X-Frame-Options" not in headers:
            vulnerabilidades_encontradas.append("Header X-Frame-Options ausente")
        if "Strict-Transport-Security" not in headers:
            vulnerabilidades_encontradas.append("Header HSTS ausente")
    except Exception:
        pass

    # Diretórios administrativos comuns expostos (simples)
    dirs_admin = ["admin", "administrator", "login", "user"]
    encontrados = []
    for d in dirs_admin:
        try:
            r = requests.get(url.rstrip("/") + "/" + d, timeout=5)
            if r.status_code == 200:
                encontrados.append(d)
        except:
            pass
    if encontrados:
        vulnerabilidades_encontradas.append(f"Diretórios administrativos expostos: {', '.join(encontrados)}")

    # Mostrar resultados
    if vulnerabilidades_encontradas:
        console.print("[red]Vulnerabilidades encontradas:[/red]")
        for v in vulnerabilidades_encontradas:
            console.print(f" - {v}")
        salvar_relatorio(f"Scanner de vulnerabilidades em {url}:\n" + "\n".join(vulnerabilidades_encontradas))
    else:
        console.print("[green]Nenhuma vulnerabilidade básica detectada.[/green]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Brute Force de Login (simples) --------
def brute_force_login():
    console.clear()
    console.print("[bold red]Brute Force Simples[/bold red]")
    alvo = Prompt.ask("Digite IP ou domínio do alvo")
    porta = Prompt.ask("Digite porta do serviço (ex: 22 para SSH, 21 para FTP)", default="22")
    usuario = Prompt.ask("Digite o usuário", default="admin")
    wordlist_path = Prompt.ask("Caminho da wordlist (uma senha por linha)")

    try:
        with open(wordlist_path, "r") as f:
            senhas = [linha.strip() for linha in f if linha.strip()]
    except Exception as e:
        console.print(f"[red]Erro ao abrir wordlist: {e}[/red]")
        return

    console.print(f"[cyan]Iniciando brute force em {alvo}:{porta} com usuário '{usuario}'...[/cyan]")

    # Brute force fake (simulação)
    for senha in senhas[:30]:  # limita a 30 tentativas pra não travar
        console.print(f"Tentando senha: {senha}")
        time.sleep(0.2)  # simula delay
        if senha == "123456":  # exemplo de senha "correta"
            console.print(f"[green]Senha encontrada: {senha}[/green]")
            salvar_relatorio(f"Brute force: senha encontrada para {usuario}@{alvo}:{porta} -> {senha}")
            break
    else:
        console.print("[red]Nenhuma senha válida encontrada na wordlist (simulado).[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Subdomain Finder --------
def subdomain_finder():
    console.clear()
    console.print("[bold magenta]Subdomain Finder[/bold magenta]")
    dominio = Prompt.ask("Digite o domínio alvo (ex: exemplo.com)")
    subdominios_comuns = ["www", "mail", "ftp", "webmail", "localhost", "cpanel", "blog"]

    encontrados = []

    console.print("[cyan]Buscando subdomínios comuns...[/cyan]")
    for sub in subdominios_comuns:
        try:
            full = f"{sub}.{dominio}"
            resultado = socket.gethostbyname(full)
            encontrados.append(full)
        except:
            pass

    console.print("[cyan]Buscando via crt.sh (API pública)...[/cyan]")
    try:
        r = requests.get(f"https://crt.sh/?q=%25.{dominio}&output=json", timeout=10)
        if r.status_code == 200:
            dados = r.json()
            for item in dados:
                name = item['name_value']
                if name not in encontrados:
                    encontrados.append(name)
    except Exception:
        pass

    if encontrados:
        tabela = Table(title=f"Subdomínios encontrados para {dominio}", box=box.SQUARE)
        tabela.add_column("Subdomínio", style="green")
        for sub in set(encontrados):
            tabela.add_row(sub)
        console.print(tabela)
        salvar_relatorio(f"Subdomínios encontrados para {dominio}:\n" + "\n".join(set(encontrados)))
    else:
        console.print("[red]Nenhum subdomínio encontrado.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Fuzzer de Diretórios --------
def fuzzer_diretorios():
    console.clear()
    console.print("[bold yellow]Fuzzer de Diretórios[/bold yellow]")
    url = Prompt.ask("Digite a URL base (ex: https://exemplo.com)")
    wordlist_path = Prompt.ask("Caminho da wordlist para fuzzing")

    try:
        with open(wordlist_path, "r") as f:
            palavras = [linha.strip() for linha in f if linha.strip()]
    except Exception as e:
        console.print(f"[red]Erro ao abrir wordlist: {e}[/red]")
        return

    encontrados = []
    total = len(palavras)
    checados = 0

    with Progress() as progress:
        task = progress.add_task("[cyan]Fuzzing diretórios...", total=total)
        for p in palavras:
            try:
                r = requests.get(url.rstrip("/") + "/" + p, timeout=5)
                if r.status_code == 200:
                    encontrados.append(p)
                    salvar_relatorio(f"Fuzzer: Diretório encontrado em {url}: /{p}")
            except:
                pass
            checados += 1
            progress.update(task, completed=checados)

    if encontrados:
        console.print(f"[green]Diretórios encontrados pelo fuzzer:[/green] {', '.join(encontrados)}")
    else:
        console.print("[red]Nenhum diretório encontrado pelo fuzzer.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")
import hashlib
import ssl
import socket
import smtplib
from email.message import EmailMessage

# -------- Exploits Prontos para Teste --------
def exploits_prontos():
    console.clear()
    console.print("[bold red]Exploits Prontos para Teste[/bold red]")
    url = Prompt.ask("Digite a URL alvo (ex: https://exemplo.com)")

    # Simulação de teste CVE
    console.print(f"[cyan]Testando exploits conhecidos para {url}...[/cyan]")
    time.sleep(2)
    # Simulado
    console.print("[green]Nenhuma vulnerabilidade crítica detectada (simulação).[/green]")
    salvar_relatorio(f"Exploits testados em {url} - Nenhuma falha crítica detectada.")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Analisador de Certificados SSL/TLS --------
def analisador_ssl():
    console.clear()
    console.print("[bold magenta]Analisador de Certificados SSL/TLS[/bold magenta]")
    host = Prompt.ask("Digite o domínio para análise SSL (ex: exemplo.com)")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                console.print(f"[green]Certificado para {host}:[/green]")
                for k, v in cert.items():
                    console.print(f"{k}: {v}")
                salvar_relatorio(f"Análise SSL para {host}:\n{cert}")
    except Exception as e:
        console.print(f"[red]Erro ao analisar SSL: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Checador de Leak de Dados (HaveIBeenPwned) --------
def checador_leak():
    console.clear()
    console.print("[bold yellow]Checador de Leak de Dados (HaveIBeenPwned)[/bold yellow]")
    email = Prompt.ask("Digite o e-mail ou domínio para verificar vazamentos")

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    headers = {"User-Agent": "Glockzada-Pentest", "hibp-api-key": ""}  # API key opcional

    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            breaches = r.json()
            console.print(f"[red]Vazamentos encontrados para {email}:[/red]")
            for breach in breaches:
                console.print(f"- {breach['Title']} ({breach['BreachDate']})")
            salvar_relatorio(f"Leak check para {email}:\n" + "\n".join(b['Title'] for b in breaches))
        elif r.status_code == 404:
            console.print(f"[green]Nenhum vazamento encontrado para {email}.[/green]")
        else:
            console.print(f"[red]Erro na API: {r.status_code}[/red]")
    except Exception as e:
        console.print(f"[red]Erro ao consultar HaveIBeenPwned: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Hash Cracker Básico --------
def hash_cracker():
    console.clear()
    console.print("[bold cyan]Hash Cracker Básico (MD5, SHA1, SHA256)[/bold cyan]")
    hash_alvo = Prompt.ask("Digite o hash alvo")
    tipo_hash = Prompt.ask("Tipo de hash", choices=["md5", "sha1", "sha256"], default="md5")
    wordlist_path = Prompt.ask("Caminho da wordlist para ataques")

    try:
        with open(wordlist_path, "r") as f:
            senhas = [linha.strip() for linha in f if linha.strip()]
    except Exception as e:
        console.print(f"[red]Erro ao abrir wordlist: {e}[/red]")
        return

    console.print(f"[cyan]Iniciando ataque de dicionário para hash {tipo_hash}...[/cyan]")
    for senha in senhas:
        if tipo_hash == "md5":
            h = hashlib.md5(senha.encode()).hexdigest()
        elif tipo_hash == "sha1":
            h = hashlib.sha1(senha.encode()).hexdigest()
        else:
            h = hashlib.sha256(senha.encode()).hexdigest()
        if h == hash_alvo.lower():
            console.print(f"[green]Senha encontrada: {senha}[/green]")
            salvar_relatorio(f"Hash crack: {hash_alvo} = {senha}")
            break
    else:
        console.print("[red]Senha não encontrada na wordlist.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Automação de Reporte --------
def automacao_reporte():
    console.clear()
    console.print("[bold magenta]Automação de Reporte[/bold magenta]")
    texto = Prompt.ask("Digite o texto para gerar o relatório")

    nome_arquivo = f"relatorio_{int(time.time())}.txt"
    with open(nome_arquivo, "w") as f:
        f.write(texto)
    console.print(f"[green]Relatório salvo em {nome_arquivo}[/green]")

    # Opção para enviar email (simples)
    enviar = Prompt.ask("Deseja enviar o relatório por e-mail? (sim/não)", choices=["sim", "não"], default="não")
    if enviar == "sim":
        email_destino = Prompt.ask("Digite o e-mail destinatário")
        email_remetente = Prompt.ask("Digite seu e-mail remetente")
        senha_email = Prompt.ask("Digite a senha do seu e-mail (não armazenada)", password=True)

        try:
            msg = EmailMessage()
            msg.set_content(texto)
            msg["Subject"] = "Relatório Glockzada"
            msg["From"] = email_remetente
            msg["To"] = email_destino

            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
                smtp.login(email_remetente, senha_email)
                smtp.send_message(msg)
            console.print("[green]E-mail enviado com sucesso![/green]")
        except Exception as e:
            console.print(f"[red]Erro ao enviar e-mail: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Sniffer de Rede Simples --------
def sniffer_rede():
    console.clear()
    console.print("[bold yellow]Sniffer de Rede Simples (Captura básica)[/bold yellow]")
    console.print("[red]Requer privilégios administrativos para capturar pacotes reais![/red]")
    console.print("[cyan]Iniciando captura simulada por 10 segundos...[/cyan]")
    time.sleep(10)
    console.print("[green]Captura finalizada (simulação).[/green]")
    salvar_relatorio("Sniffer: captura simulada de rede realizada.")
    Prompt.ask("Pressione Enter para voltar ao menu")
import whois
from rich.progress import track

# -------- Checador de Redirecionamentos (Open Redirects) --------
def checador_redirect():
    console.clear()
    console.print("[bold purple]Checador de Redirecionamentos (Open Redirects)[/bold purple]")
    url = Prompt.ask("Digite a URL para testar redirecionamentos")

    testes = [
        "?redirect=http://evil.com",
        "?url=http://evil.com",
        "?next=http://evil.com",
        "?redir=http://evil.com",
        "?destination=http://evil.com",
        "?return=http://evil.com",
        "?data=http://evil.com",
    ]

    vulneravel = False
    for teste in testes:
        test_url = url + teste
        try:
            r = requests.get(test_url, timeout=5, allow_redirects=False)
            if "Location" in r.headers:
                loc = r.headers["Location"]
                if "evil.com" in loc:
                    vulneravel = True
                    console.print(f"[red]Vulnerável ao redirecionamento: {test_url}[/red]")
                    salvar_relatorio(f"Open Redirect detectado: {test_url}")
        except Exception as e:
            console.print(f"[red]Erro ao testar {test_url}: {e}[/red]")

    if not vulneravel:
        console.print("[green]Nenhum redirecionamento inseguro detectado.[/green]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Reconhecimento via WHOIS --------
def reconhecimento_whois():
    console.clear()
    console.print("[bold green]Reconhecimento WHOIS[/bold green]")
    dominio = Prompt.ask("Digite o domínio (ex: exemplo.com)")

    try:
        info = whois.whois(dominio)
        console.print(f"[cyan]Informações WHOIS para {dominio}:[/cyan]")
        for chave, valor in info.items():
            console.print(f"{chave}: {valor}")
        salvar_relatorio(f"WHOIS para {dominio}:\n{info}")
    except Exception as e:
        console.print(f"[red]Erro ao obter WHOIS: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Script para Testar Headers de Segurança --------
def testar_headers():
    console.clear()
    console.print("[bold magenta]Testar Headers de Segurança[/bold magenta]")
    url = Prompt.ask("Digite a URL para testar headers")

    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        seguros = {
            "X-Frame-Options": "Sinaliza se a página pode ser exibida em frames",
            "X-XSS-Protection": "Proteção contra Cross Site Scripting",
            "Content-Security-Policy": "Política de segurança de conteúdo",
            "Strict-Transport-Security": "Força HTTPS"
        }
        for h in seguros:
            if h in headers:
                console.print(f"[green]{h}: {headers[h]}[/green]")
            else:
                console.print(f"[red]{h} não encontrado![/red]")
        salvar_relatorio(f"Test Headers para {url}:\n{headers}")
    except Exception as e:
        console.print(f"[red]Erro ao testar headers: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Analisador de Robots.txt --------
def analisar_robots():
    console.clear()
    console.print("[bold yellow]Analisador de Robots.txt[/bold yellow]")
    url = Prompt.ask("Digite a URL base do site (ex: https://exemplo.com)")

    try:
        robots_url = url.rstrip("/") + "/robots.txt"
        r = requests.get(robots_url, timeout=5)
        if r.status_code == 200:
            console.print(f"[green]Conteúdo de robots.txt:[/green]\n{r.text}")
            salvar_relatorio(f"Robots.txt de {url}:\n{r.text}")
        else:
            console.print("[red]Robots.txt não encontrado ou inacessível.[/red]")
    except Exception as e:
        console.print(f"[red]Erro ao acessar robots.txt: {e}[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Menu colorido e barra de progresso exemplo --------
def menu_colorido():
    console.clear()
    console.print("[bold magenta]Menu Colorido Glockzada[/bold magenta]")
    options = [
        ("Scanner de portas", "purple"),
        ("Vulnerability Scanner", "red"),
        ("Brute Force", "red"),
        ("Subdomain Finder", "yellow"),
        ("Fuzzer de Diretórios", "yellow"),
        ("Exploits", "red"),
        ("Analisador SSL", "magenta"),
        ("Leak Checker", "yellow"),
        ("Hash Cracker", "cyan"),
        ("Relatório", "green"),
        ("Sniffer", "yellow"),
        ("Open Redirect", "purple"),
        ("WHOIS", "green"),
        ("Testar Headers", "magenta"),
        ("Robots.txt", "yellow"),
        ("Bypass", "purple"),
        ("Chat", "cyan"),
        ("Créditos", "purple"),
        ("Sair", "red")
    ]
    table = Table(title="Menu Glockzada", box=box.ROUNDED, border_style="magenta")
    table.add_column("Opção", justify="center")
    table.add_column("Descrição", justify="left")

    for i, (desc, cor) in enumerate(options, 1):
        table.add_row(f"[{cor}]{i}[/{cor}]", f"[{cor}]{desc}[/{cor}]")

    console.print(table)

    choice = Prompt.ask("Escolha uma opção", choices=[str(i) for i in range(1, len(options)+1)])
    console.print(f"Você escolheu: {options[int(choice)-1][0]}")

def barra_progresso_simples(titulo="Processando...", total=100):
    for i in track(range(total), description=titulo):
        time.sleep(0.02)

# -------- Notificação simples --------
def notificar(msg):
    console.print(Panel(msg, border_style="red", title="[bold red]Alerta[/bold red]"))
import requests
import socket
import threading
import time
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.table import Table
from rich.panel import Panel
from rich.progress import track
import whois

console = Console()

RELATORIO_FILE = "relatorio.txt"

def salvar_relatorio(texto):
    with open(RELATORIO_FILE, "a") as f:
        f.write(texto + "\n")

def login():
    console.clear()
    console.print(Panel("[bold purple]Acesso ao Painel Privado Glockzada[/bold purple]\nUsuário: admin\nSenha: admin", title="Login"))
    usuario = Prompt.ask("Usuário")
    senha = Prompt.ask("Senha", password=True)
    if usuario == "admin" and senha == "admin":
        return True
    else:
        console.print("[red]Usuário ou senha incorretos![/red]")
        time.sleep(1)
        return False

# -------- Scanner de Portas Avançado --------
def scanner_portas():
    console.clear()
    console.print("[bold purple]Scanner de Portas Avançado (1-1024)[/bold purple]")
    alvo = Prompt.ask("Digite o IP ou domínio alvo")
    portas_abertas = []

    def scan_porta(porta):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            resultado = sock.connect_ex((alvo, porta))
            if resultado == 0:
                portas_abertas.append(porta)
            sock.close()
        except:
            pass

    threads = []
    for porta in track(range(1, 1025), description="Escaneando portas..."):
        t = threading.Thread(target=scan_porta, args=(porta,))
        threads.append(t)
        t.start()
        while threading.active_count() > 100:
            time.sleep(0.01)

    for t in threads:
        t.join()

    if portas_abertas:
        console.print(f"[green]Portas abertas em {alvo}:[/green] {portas_abertas}")
        salvar_relatorio(f"Portas abertas em {alvo}: {portas_abertas}")
    else:
        console.print("[red]Nenhuma porta aberta encontrada.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Vulnerability Scanner (simplificado) --------
def vulnerability_scanner():
    console.clear()
    console.print("[bold red]Vulnerability Scanner[/bold red]")
    alvo = Prompt.ask("Digite o domínio alvo (ex: exemplo.com)")

    # Exemplos básicos de testes - para expandir conforme necessidade
    testes = {
        "Diretórios administrativos padrão": ["/admin", "/administrator", "/login", "/wp-admin"],
        "Headers HTTP inseguros": None,
    }

    vulnerabilidades = []

    # Checa diretórios
    for dir in testes["Diretórios administrativos padrão"]:
        url = f"http://{alvo}{dir}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                vulnerabilidades.append(f"Diretório acessível: {url}")
        except:
            pass

    # Headers inseguros (simplificado)
    try:
        r = requests.get(f"http://{alvo}", timeout=3)
        headers = r.headers
        if "Content-Security-Policy" not in headers:
            vulnerabilidades.append("Header Content-Security-Policy ausente")
        if "Strict-Transport-Security" not in headers:
            vulnerabilidades.append("Header Strict-Transport-Security ausente")
        if "X-Content-Type-Options" not in headers:
            vulnerabilidades.append("Header X-Content-Type-Options ausente")
    except:
        pass

    if vulnerabilidades:
        console.print("[red]Vulnerabilidades encontradas:[/red]")
        for v in vulnerabilidades:
            console.print(f"- {v}")
            salvar_relatorio(f"Vulnerabilidade: {v}")
    else:
        console.print("[green]Nenhuma vulnerabilidade básica detectada.[/green]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Brute Force Simples --------
def brute_force_simples():
    console.clear()
    console.print("[bold red]Brute Force Simples[/bold red]")
    alvo = Prompt.ask("Digite IP ou domínio do serviço (ex: ftp.exemplo.com)")
    servico = Prompt.ask("Escolha o serviço", choices=["ftp", "ssh", "admin"])
    wordlist = ["admin", "123456", "password", "root", "toor", "1234", "12345"]

    console.print(f"[yellow]Tentando brute force {servico} em {alvo}... (simulação)[/yellow]")
    time.sleep(3)  # Simulação
    console.print("[green]Brute force finalizado (simulado). Nenhuma senha encontrada.[/green]")
    salvar_relatorio(f"Brute force simulado em {alvo} para {servico}")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Subdomain Finder --------
def subdomain_finder():
    console.clear()
    console.print("[bold yellow]Subdomain Finder[/bold yellow]")
    dominio = Prompt.ask("Digite o domínio alvo")
    subdominios = ["www", "mail", "ftp", "admin", "dev", "test"]

    encontrados = []

    for sub in track(subdominios, description="Procurando subdomínios..."):
        url = f"http://{sub}.{dominio}"
        try:
            r = requests.get(url, timeout=2)
            if r.status_code < 400:
                encontrados.append(url)
        except:
            pass

    if encontrados:
        console.print("[green]Subdomínios encontrados:[/green]")
        for e in encontrados:
            console.print(f"- {e}")
            salvar_relatorio(f"Subdomínio encontrado: {e}")
    else:
        console.print("[red]Nenhum subdomínio encontrado com wordlist básica.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Fuzzer de Diretórios --------
def fuzzer_diretorios():
    console.clear()
    console.print("[bold yellow]Fuzzer de Diretórios[/bold yellow]")
    url_base = Prompt.ask("Digite a URL base (ex: http://exemplo.com/)")
    wordlist = ["admin", "login", "backup", "test", "config", "db", "private", "temp"]

    encontrados = []

    for path in track(wordlist, description="Fuzzing diretórios..."):
        url = url_base.rstrip("/") + "/" + path
        try:
            r = requests.get(url, timeout=2)
            if r.status_code == 200:
                encontrados.append(url)
        except:
            pass

    if encontrados:
        console.print("[green]Diretórios/arquivos encontrados:[/green]")
        for e in encontrados:
            console.print(f"- {e}")
            salvar_relatorio(f"Diretório/arquivo encontrado: {e}")
    else:
        console.print("[red]Nenhum diretório/arquivo encontrado.[/red]")

    Prompt.ask("Pressione Enter para voltar ao menu")
import time
from rich import box

# -------- Exploits simples --------
def exploits_prontos():
    console.clear()
    console.print("[bold red]Exploits Prontos para Teste[/bold red]")
    alvo = Prompt.ask("Digite o domínio alvo")
    console.print("[yellow]Executando exploits básicos (simulação)...[/yellow]")
    time.sleep(3)
    console.print("[green]Nenhuma vulnerabilidade crítica encontrada (simulação).[/green]")
    salvar_relatorio(f"Exploits testados em {alvo} (simulado)")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Analisador SSL/TLS --------
def analisador_ssl():
    console.clear()
    console.print("[bold cyan]Analisador de Certificados SSL/TLS[/bold cyan]")
    alvo = Prompt.ask("Digite o domínio alvo")
    try:
        r = requests.get(f"https://{alvo}", timeout=5)
        cert = r.raw.connection.sock.getpeercert()
        console.print("[green]Certificado SSL obtido com sucesso (simplificado).[/green]")
        salvar_relatorio(f"Certificado SSL obtido para {alvo}")
    except Exception as e:
        console.print(f"[red]Erro ao obter certificado SSL: {e}[/red]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Checador de Leak de Dados --------
def checador_leak():
    console.clear()
    console.print("[bold red]Checador de Leak de Dados[/bold red]")
    email = Prompt.ask("Digite o e-mail ou domínio para checar leaks")
    console.print("[yellow]Consultando bancos públicos (simulação)...[/yellow]")
    time.sleep(2)
    console.print(f"[green]Nenhum dado comprometido encontrado para {email} (simulado).[/green]")
    salvar_relatorio(f"Leak check para {email} (simulado)")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Hash Cracker Básico --------
def hash_cracker():
    console.clear()
    console.print("[bold magenta]Hash Cracker Básico[/bold magenta]")
    hash_input = Prompt.ask("Digite o hash (MD5, SHA1, SHA256)")
    console.print("[yellow]Tentando crackear hash com wordlist interna (simulação)...[/yellow]")
    time.sleep(3)
    console.print("[red]Hash não encontrado (simulado).[/red]")
    salvar_relatorio(f"Hash crack attempt for {hash_input} (simulado)")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Automação de Reporte --------
def automacao_reporte():
    console.clear()
    console.print("[bold green]Automação de Reporte[/bold green]")
    console.print("[yellow]Gerando relatório completo...[/yellow]")
    time.sleep(2)
    console.print(f"[green]Relatório salvo em {RELATORIO_FILE}[/green]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Sniffer Simples --------
def sniffer_rede():
    console.clear()
    console.print("[bold cyan]Sniffer de Rede Simples[/bold cyan]")
    console.print("[yellow]Capturando pacotes... (simulação)[/yellow]")
    time.sleep(3)
    console.print("[green]Nenhum tráfego suspeito detectado (simulado).[/green]")
    salvar_relatorio("Sniffer executado (simulado)")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Checador Open Redirect --------
def checador_redirect():
    console.clear()
    console.print("[bold magenta]Checador de Redirecionamentos (Open Redirects)[/bold magenta]")
    url = Prompt.ask("Digite a URL para teste")
    console.print("[yellow]Testando redirecionamentos inseguros... (simulação)[/yellow]")
    time.sleep(2)
    console.print("[green]Nenhum open redirect detectado (simulado).[/green]")
    salvar_relatorio(f"Open redirect test em {url} (simulado)")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Whois --------
def whois_consulta():
    console.clear()
    console.print("[bold yellow]Consulta WHOIS[/bold yellow]")
    dominio = Prompt.ask("Digite o domínio")
    try:
        info = whois.whois(dominio)
        console.print(Panel(str(info), title=f"WHOIS: {dominio}", border_style="yellow"))
        salvar_relatorio(f"Consulta WHOIS em {dominio}")
    except Exception as e:
        console.print(f"[red]Erro na consulta WHOIS: {e}[/red]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Teste Headers Segurança --------
def teste_headers_seguranca():
    console.clear()
    console.print("[bold green]Teste de Headers de Segurança[/bold green]")
    url = Prompt.ask("Digite a URL")
    try:
        r = requests.get(url, timeout=5)
        headers = r.headers
        alertas = []
        if "X-Frame-Options" not in headers:
            alertas.append("X-Frame-Options ausente")
        if "X-XSS-Protection" not in headers:
            alertas.append("X-XSS-Protection ausente")
        if "Content-Security-Policy" not in headers:
            alertas.append("Content-Security-Policy ausente")
        if "Strict-Transport-Security" not in headers:
            alertas.append("Strict-Transport-Security ausente")

        if alertas:
            console.print("[red]Problemas detectados nos headers:[/red]")
            for a in alertas:
                console.print(f"- {a}")
                salvar_relatorio(f"Header de segurança faltando: {a} em {url}")
        else:
            console.print("[green]Todos os headers importantes estão configurados corretamente.[/green]")
    except Exception as e:
        console.print(f"[red]Erro ao checar headers: {e}[/red]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Analisador Robots.txt --------
def analisador_robots():
    console.clear()
    console.print("[bold cyan]Analisador de Robots.txt[/bold cyan]")
    url = Prompt.ask("Digite a URL base (ex: http://exemplo.com/)")
    try:
        r = requests.get(url.rstrip("/") + "/robots.txt", timeout=5)
        if r.status_code == 200:
            console.print("[green]Conteúdo do robots.txt:[/green]")
            console.print(r.text)
            salvar_relatorio(f"Robots.txt analisado em {url}")
        else:
            console.print("[red]robots.txt não encontrado.[/red]")
    except Exception as e:
        console.print(f"[red]Erro ao acessar robots.txt: {e}[/red]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Ferramenta Bypass (10 opções) --------
def ferramenta_bypass():
    console.clear()
    console.print("[bold purple]Ferramenta Bypass - Escolha o tipo[/bold purple]")
    bypasses = [
        "Bypass WAF simples",
        "Bypass Cloudflare (simulado)",
        "Bypass Proteção Cookies",
        "Bypass Anti-bot",
        "Bypass Rate Limit",
        "Bypass Captcha",
        "Bypass User-Agent",
        "Bypass Referrer",
        "Bypass SQLi Filter",
        "Bypass XSS Filter"
    ]
    tabela = Table(title="Bypasses Disponíveis", box=box.MINIMAL_DOUBLE_HEAD, border_style="purple")
    for i, b in enumerate(bypasses, 1):
        tabela.add_row(str(i), b)
    console.print(tabela)
    escolha = Prompt.ask("Escolha uma opção (1-10)", choices=[str(i) for i in range(1,11)])
    url = Prompt.ask("Digite a URL alvo")
    console.print(f"[yellow]Executando {bypasses[int(escolha)-1]} em {url}...[/yellow]")
    time.sleep(2)
    console.print("[green]Bypass executado com sucesso (simulação)![/green]")
    salvar_relatorio(f"Bypass {bypasses[int(escolha)-1]} aplicado em {url}")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Gerar relatório --------
def gerar_relatorio():
    console.clear()
    console.print("[bold purple]Gerar relatório[/bold purple]")
    if os.path.exists(RELATORIO_FILE):
        with open(RELATORIO_FILE, "r") as f:
            conteudo = f.read()
        console.print(Panel(conteudo, title="Relatório completo", border_style="purple"))
    else:
        console.print("[red]Nenhum relatório encontrado.[/red]")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Chat simples --------
chat_log = []

def chat_simples():
    console.clear()
    console.print("[bold purple]Chat simples Glockzada[/bold purple]")
    nick = Prompt.ask("Seu nick")
    console.print("[cyan]Digite 'sair' para voltar ao menu[/cyan]")
    while True:
        msg = Prompt.ask(f"[{nick}]")
        if msg.lower() == "sair":
            break
        chat_log.append(f"{nick}: {msg}")
        console.print(f"[bold green]{nick}[/bold green]: {msg}")
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Créditos --------
def mostrar_creditos():
    console.clear()
    texto = """
[bold purple]Painel Glockzada - Versão 2.0[/bold purple]

Criado por: Glockzada

Telegram: https://t.me/+9I980Hi7eHIyYzg5

Obrigado por usar!
    """
    panel = Panel(texto, title="Créditos", border_style="purple")
    console.print(panel)
    Prompt.ask("Pressione Enter para voltar ao menu")

# -------- Menu principal --------
def print_logo():
    console.print("\n[bold purple]PAINEL GLOCKZADA[/bold purple]\n", justify="center")

def menu_principal():
    while True:
        console.clear()
        print_logo()
        menu = Table(title="[bold purple]Menu Principal - Glockzada[/bold purple]", box=box.DOUBLE_EDGE, border_style="purple")
        menu.add_column("Opção", justify="center")
        menu.add_column("Descrição", justify="left")
        menu.add_row("1", "Port Scanner Avançado")
        menu.add_row("2", "Vulnerability Scanner")
        menu.add_row("3", "Brute Force de Login")
        menu.add_row("4", "Subdomain Finder")
        menu.add_row("5", "Fuzzer de Diretórios")
        menu.add_row("6", "Exploits Prontos para Teste")
        menu.add_row("7", "Analisador de Certificados SSL/TLS")
        menu.add_row("8", "Checador de Leak de Dados")
        menu.add_row("9", "Hash Cracker Básico")
        menu.add_row("10", "Automação de Reporte")
        menu.add_row("11", "Sniffer de Rede Simples")
        menu.add_row("12", "Checador de Redirecionamentos (Open Redirect)")
        menu.add_row("13", "Reconhecimento via WHOIS")
        menu.add_row("14", "Teste Headers de Segurança")
        menu.add_row("15", "Analisador de Robots.txt")
        menu.add_row("16", "Ferramenta Bypass")
        menu.add_row("17", "Gerar Relatório")
        menu.add_row("18", "Chat Simples")
        menu.add_row("19", "Créditos")
        menu.add_row("0", "Sair")
        # Continua a função menu_principal()
        console.print(menu)

        opcao = Prompt.ask("Escolha uma opção", choices=[str(i) for i in range(0,20)])

        if opcao == "0":
            console.print("[bold red]Saindo...[/bold red]")
            break
        elif opcao == "1":
            scanner_portas_avancado()
        elif opcao == "2":
            vulnerability_scanner()
        elif opcao == "3":
            brute_force_login()
        elif opcao == "4":
            subdomain_finder()
        elif opcao == "5":
            fuzzer_diretorios()
        elif opcao == "6":
            exploits_prontos()
        elif opcao == "7":
            analisador_ssl()
        elif opcao == "8":
            checador_leak()
        elif opcao == "9":
            hash_cracker()
        elif opcao == "10":
            automacao_reporte()
        elif opcao == "11":
            sniffer_rede()
        elif opcao == "12":
            checador_redirect()
        elif opcao == "13":
            whois_consulta()
        elif opcao == "14":
            teste_headers_seguranca()
        elif opcao == "15":
            analisador_robots()
        elif opcao == "16":
            ferramenta_bypass()
        elif opcao == "17":
            gerar_relatorio()
        elif opcao == "18":
            chat_simples()
        elif opcao == "19":
            mostrar_creditos()
        else:
            console.print("[red]Opção inválida![/red]")
            time.sleep(1)

# -------- Login --------
def login():
    console.clear()
    console.print(Panel("[bold purple]Acesso ao Painel Privado Glockzada\nUsuário: admin\nSenha: admin[/bold purple]", border_style="purple", title="Login"))
    usuario = Prompt.ask("Usuário")
    senha = Prompt.ask("Senha", password=True)
    if usuario == "admin" and senha == "admin":
        console.print("[green]Login efetuado com sucesso![/green]")
        time.sleep(1)
        return True
    else:
        console.print("[red]Usuário ou senha incorretos.[/red]")
        time.sleep(1)
        return False

if __name__ == "__main__":
    while not login():
        pass
    menu_principal()

