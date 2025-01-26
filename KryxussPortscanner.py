import socket
import os
import re
import ssl
import dns.resolver
import http.client
import requests

def print_box(message):
    length = len(message) + 4
    print("+" + "-" * length + "+")
    print("|  " + message + "  |")
    print("+" + "-" * length + "+")

def print_separator():
    print("\n" + "="*50 + "\n")

def banner():
    print("""

     ) (       ) (                   )    )     (     
  ( /( )\ ) ( /( )\ )  (    (     ( /( ( /(     )\ )  
  )\()|()/( )\()|()/(  )\   )\    )\()))\())(  (()/(  
|((_)\ /(_)|(_)\ /(_)|((_|(((_)( ((_)\((_)\ )\  /(_)) 
|_ ((_|_))__ ((_|_)) )\___)\ _ )\ _((_)_((_|(_)(_))   
| |/ /| _ \ \ / / __((/ __(_)_\(_) \| | \| | __| _ \  
  ' < |   /\ V /\__ \| (__ / _ \ | .` | .` | _||   /  
 _|\_\|_|_\ |_| |___/ \___/_/ \_\|_|\_|_|\_|___|_|_\  
                                                      

    """)

def get_ip(domain):
    try:
        print_separator()
        print("[🔍] Buscando IPv4...")
        ip = socket.gethostbyname(domain)
        print_box(f"IPv4 de {domain}: {ip}")
        return ip
    except:
        print_box("❌ No se pudo obtener la dirección IP del dominio.")
        return None

def cloudflare(domain):
    try:
        print_separator()
        print("[🛡️] Intentando bypasear Cloudflare...")
        url = f"https://www.crimeflarre.org:82/cgi-bin/cfsearch.cgi"
        data = {
            "cfS": domain
        }
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        response = requests.post(url, data=data, headers=headers)
        ip = re.search(r"IP Address: (.*)", response.text).group(1)
        print_box(f"IP real detrás de Cloudflare: {ip}")
    except:
        print_box("❌ No se pudo obtener la IP real del dominio.")

def port_scan(ip):
    try:
        print_separator()
        print("[🔍] Iniciando escaneo de puertos...")
        open_ports = []
        total_ports = 65535
        
        for port in range(1, total_ports + 1):
            if port % 1000 == 0:
                progress = (port / total_ports) * 100
                print(f"\r[{'#' * int(progress/2)}{' ' * (50-int(progress/2))}] {progress:.1f}%", end='')
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            if s.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            s.close()
        
        print("\n")  # New line after progress bar
        if open_ports:
            print_box("Puertos abiertos encontrados:")
            for port in open_ports:
                print(f"[✓] Puerto {port}")
        else:
            print_box("No se encontraron puertos abiertos")
    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido por el usuario")
    except:
        print_box("❌ Error durante el escaneo de puertos")

def check_ssl(domain):
    print_separator()
    print("[🔒] Verificando certificado SSL...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print_box("Información del certificado SSL:")
                print(f"[✓] Emisor: {dict(x[0] for x in cert['issuer'])['commonName']}")
                print(f"[✓] Expira: {cert['notAfter']}")
    except:
        print_box("❌ No se pudo verificar el certificado SSL")

def check_headers(domain):
    print_separator()
    print("[🔍] Analizando headers HTTP...")
    try:
        conn = http.client.HTTPSConnection(domain)
        conn.request("GET", "/")
        response = conn.getresponse()
        print_box("Headers encontrados:")
        for header, value in response.getheaders():
            if header.lower() in ['server', 'x-powered-by', 'x-framework']:
                print(f"[!] {header}: {value}")
    except:
        print_box("❌ No se pudieron obtener los headers")

def check_dns_records(domain):
    print_separator()
    print("[🔍] Buscando registros DNS...")
    records = ['A', 'MX', 'NS', 'TXT', 'SOA']
    try:
        for record in records:
            try:
                answers = dns.resolver.resolve(domain, record)
                print(f"\n[✓] Registros {record}:")
                for rdata in answers:
                    print(f"    {rdata}")
            except:
                continue
    except:
        print_box("❌ Error al buscar registros DNS")

def detect_waf(domain):
    print_separator()
    print("[🛡️] Detectando WAF...")
    waf_signatures = {
        'cloudflare': ['__cfduid', 'cloudflare-nginx'],
        'sucuri': ['sucuri', 'cloudproxy'],
        'incapsula': ['incap_ses', 'visid_incap'],
        'akamai': ['akamai']
    }
    
    try:
        conn = http.client.HTTPSConnection(domain)
        conn.request("GET", "/")
        response = conn.getresponse()
        headers = str(response.getheaders()).lower()
        
        found_waf = False
        for waf, sigs in waf_signatures.items():
            if any(sig in headers for sig in sigs):
                print_box(f"WAF detectado: {waf.upper()}")
                found_waf = True
        
        if not found_waf:
            print_box("No se detectó ningún WAF conocido")
    except:
        print_box("❌ Error al detectar WAF")

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    banner()
    print_box("Bienvenido al escaner de Kryxuss")
    
    domain = input("\n[?] Ingrese el dominio del servidor: ")
    ip = get_ip(domain)
    
    if ip:
        while True:
            print_separator()
            print("[1] Escanear puertos")
            print("[2] Verificar SSL")
            print("[3] Analizar headers")
            print("[4] Buscar registros DNS")
            print("[5] Detectar WAF")
            print("[6] Bypass Cloudflare")
            print("[0] Salir")
            
            option = input("\n[?] Seleccione una opción: ")
            
            if option == "1":
                port_scan(ip)
            elif option == "2":
                check_ssl(domain)
            elif option == "3":
                check_headers(domain)
            elif option == "4":
                check_dns_records(domain)
            elif option == "5":
                detect_waf(domain)
            elif option == "6":
                cloudflare(domain)
            elif option == "0":
                break
        
    print_separator()
    print("[👋] Gracias por usar Kryxuss Port Scanner\n")

if __name__ == "__main__":
    main()

# Kryxuss 2025