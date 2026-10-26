import os
import re
import sys
import math
import shutil
import urllib.request
import urllib.parse

RST = "\033[0m"
GRN = "\033[38;5;46m"
GRN_B = "\033[1;38;5;46m"
WHT = "\033[1m"

BANNER = """     _ _ _____ _ _
    | \\ | | |_ _| | | | |
    | \\| | | | | |_
    | | |\\ | | | |  _|
    |_| \\_| |_| |_|\\__|"""

FERRAMENTAS = [
    ("1", "SQLMap",          "Automatização de SQL Injection"),
    ("2", "Bettercap",       "MITM / Sniffer / Análise de Rede"),
    ("3", "Photo Password",  "Extração e quebra de senhas"),
    ("4", "Site Clone Scan", "Copia, escaneia e replica um site"),
    ("5", "Sair",            "Encerra a sessão"),
]


def rgb(texto, freq=25):
    linhas = texto.split("\n")
    saida = []
    pos = 0
    for linha in linhas:
        construida = ""
        for ch in linha:
            if ch != " ":
                r = int(127 + 127 * math.sin(3.14 * pos / freq))
                g = int(127 + 127 * math.sin(3.14 * pos / freq + 2))
                b = int(127 + 127 * math.sin(3.14 * pos / freq + 4))
                construida += "\033[38;2;%d;%d;%dm%s" % (r, g, b, ch)
            else:
                construida += ch
            pos += 1
        saida.append(construida + RST)
    return "\n".join(saida)


def verde(texto, bold=False):
    return (GRN_B if bold else GRN) + texto + RST


def limpar():
    os.system("clear" if os.name != "nt" else "cls")


def cabecalho(titulo):
    limpar()
    print()
    print(rgb(BANNER, freq=18))
    print(rgb("N E T W O R K   H A C K I N G   T O O L K I T".center(56)))
    print()
    print("  " + rgb(":: " + titulo + " ::"))
    print("  " + verde("─" * 54))
    print()


def pausa():
    input(verde("\n  [ENTER] voltar ao menu principal... ", bold=True))


def entrada(rotulo, padrao=None):
    valor = input(verde("  [-] " + rotulo + ": ")).strip()
    if not valor and padrao:
        return padrao
    return valor


def menu():
    cabecalho("MENU PRINCIPAL")
    for cod, nome, desc in FERRAMENTAS:
        print("  " + verde("[%s] " % cod, bold=True) + rgb(nome.ljust(18)) + verde(desc))
    print()
    try:
        return input("  " + verde("NTH", bold=True) + verde(" > ")).strip()
    except (KeyboardInterrupt, EOFError):
        return "5"


def rodar(comando, nome):
    if shutil.which(comando.split()[0]) is None:
        cabecalho(nome)
        print(verde("  [!] Ferramenta não encontrada no sistema: %s" % comando.split()[0]))
        print(verde("  [i] Instale com: sudo apt install %s" % comando.split()[0]))
        pausa()
        return
    os.system(comando)
    pausa()


def ferr_sqlmap():
    cabecalho("SQLMAP — SQL INJECTION")
    url = entrada("URL alvo")
    if not url:
        print(verde("  [!] Nenhuma URL informada."))
        pausa()
        return
    nivel = entrada("Nível [1-5] (padrão 3)", "3")
    rodar("sqlmap -u '%s' --batch --level=%s" % (url, nivel), "SQLMap")


def ferr_bettercap():
    cabecalho("BETTERCAP — REDE / MITM")
    iface = entrada("Interface de rede", "eth0")
    rodar("sudo bettercap -iface %s" % iface, "Bettercap")


def ferr_photo_password():
    cabecalho("PHOTO PASSWORD — QUEBRA DE SENHAS")
    alvo = entrada("Arquivo de hash")
    if not alvo or not os.path.exists(alvo):
        print(verde("  [!] Arquivo não encontrado."))
        pausa()
        return
    wordlist = entrada("Wordlist", "/usr/share/wordlists/rockyou.txt")
    if not os.path.exists(wordlist):
        print(verde("  [!] Wordlist não encontrada: %s" % wordlist))
        pausa()
        return
    rodar("john --wordlist=%s %s" % (wordlist, alvo), "Photo Password")


def baixar(url):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            conteudo = resp.read()
            return conteudo.decode("utf-8", "ignore"), resp.geturl()
    except Exception:
        return None, None


def salvar_recurso(url, pasta):
    caminho = urllib.parse.urlparse(url).path.strip("/")
    if not caminho:
        return False
    destino = os.path.join(pasta, caminho)
    os.makedirs(os.path.dirname(destino) or pasta, exist_ok=True)
    conteudo, _ = baixar(url)
    if conteudo is None:
        return False
    with open(destino, "wb") as f:
        f.write(conteudo)
    return True


def ferr_clone():
    cabecalho("SITE CLONE SCAN")
    site = entrada("URL do site alvo")
    if not site:
        print(verde("  [!] Nenhuma URL informada."))
        pausa()
        return
    if not site.startswith("http"):
        site = "http://" + site
    host = urllib.parse.urlparse(site).netloc
    pasta = "replica_" + host.replace(":", "_").replace(".", "_")
    os.makedirs(pasta, exist_ok=True)

    print(verde("\n  [1/4] Baixando página principal..."))
    html, url_final = baixar(site)
    if not html:
        print(verde("  [!] Falha ao conectar em %s" % site))
        pausa()
        return

    print(verde("  [2/4] Escaneando recursos..."))
    achados = sorted(set(re.findall(r'(?:src|href)\s*=\s*["\']([^"\']+)["\']', html)))
    recursos = []
    for link in achados:
        if link.startswith("//"):
            link = "http:" + link
        elif link.startswith("/"):
            link = urllib.parse.urljoin(url_final, link)
        elif link.startswith("http"):
            if urllib.parse.urlparse(link).netloc != host:
                continue
        else:
            continue
        link = link.split("#")[0]
        if link and link not in recursos:
            recursos.append(link)
    print(verde("        %d recursos encontrados" % len(recursos)))

    print(verde("  [3/4] Baixando recursos para a réplica..."))
    ok, falha = 0, 0
    for r in recursos:
        if salvar_recurso(r, pasta):
            ok += 1
            print(verde("        [+] %s" % r))
        else:
            falha += 1
            print(verde("        [-] %s" % r))

    print(verde("  [4/4] Gerando index.html e relatório..."))
    index = re.sub(r"<title>.*?</title>", "<title>REPLICA — NTH</title>", html, flags=re.S)
    with open(os.path.join(pasta, "index.html"), "w") as f:
        f.write(index)

    relatorio = os.path.join(pasta, "scan.txt")
    with open(relatorio, "w") as f:
        f.write("NTH — Site Clone Scan\n")
        f.write("Alvo: %s\n" % url_final)
        f.write("Recursos encontrados: %d\n" % len(recursos))
        f.write("Baixados: %d | Falhas: %d\n\n" % (ok, falha))
        f.write("\n".join(recursos))

    cabecalho("SITE CLONE SCAN — CONCLUÍDO")
    print(verde("  [✔] Réplica salva em:  %s" % pasta, bold=True))
    print(verde("  [✔] Relatório de scan: %s" % relatorio, bold=True))
    print(verde("  [✔] Recursos: %d baixados / %d falhas" % (ok, falha)))
    pausa()


def sair():
    cabecalho("ENCERRANDO")
    print(rgb("N T H".center(56)))
    print(verde("  Sessão encerrada com segurança.", bold=True))
    print()
    sys.exit(0)


def main():
    acoes = {
        "1": ferr_sqlmap,
        "2": ferr_bettercap,
        "3": ferr_photo_password,
        "4": ferr_clone,
        "5": sair,
    }
    while True:
        op = menu()
        acao = acoes.get(op)
        if acao:
            acao()
        else:
            cabecalho("OPÇÃO INVÁLIDA")
            print(verde("  [!] Escolha um número de 1 a 5."))
            pausa()


if __name__ == "__main__":
    main()
