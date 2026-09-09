#!/usr/bin/env python3
"""
Script de reconocimiento completo para redes industriales.
Objetivo: Simular un ataque realista de reconocimiento en un entorno ICS.
"""

import subprocess
import os
import sys
import re
from datetime import datetime

# --- CONFIGURACION ---
# Barrido del rango agregado completo: con la topologia en estrella el
# atacante ya no ve subredes /24 compartidas, solo sabe (por su propia
# tabla de rutas) que todo 192.168.0.0/16 es alcanzable via el monitor.
# Un ping sweep (-sn) sobre un /16 sigue siendo rapido en la practica
# (el 99% del rango no tiene ruta real mas alla del monitor, asi que el
# kernel responde "red inalcanzable" casi al instante en vez de esperar
# un timeout completo), y es mas realista como reconocimiento "a ciegas"
# que enumerar a mano las 5 subredes /29 reales (lo cual asumiria
# conocimiento previo de la topologia exacta).
SUBNETS = ["192.168.200.0/21"]
OUTPUT_DIR = "./attack1/nmap"  # Ruta relativa dentro de /scripts
NMAP_FAST_ARGS = ["-p", "1-1000,5020,8080,5432", "-sV", "--open", "-T3"]  # Escaneo rapido
NMAP_EXHAUSTIVE_ARGS = ["-p-", "-sV", "--open", "-T4"]  # Escaneo exhaustivo (solo si hay puertos abiertos)
CRITICAL_PORTS = ["502", "5020", "80", "8080", "5432", "22", "443"]  # Puertos criticos para escaneo de vulnerabilidades
ATTACKER_IP = "192.168.204.3"  # IP del contenedor attacker_node (net_attacker, topologia en estrella)
OPEN_PORT_LINE = re.compile(r"^\d+/(tcp|udp)\s+open\b", re.MULTILINE)

# --- FUNCIONES ---
def log_message(message, level="INFO"):
    """Imprime un mensaje con timestamp y nivel de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)

def run_streaming(cmd, label):
    """Ejecuta un comando mostrando su salida EN VIVO, linea a linea, y
    ademas la devuelve entera como string para que quien llame pueda
    parsearla (p.ej. para extraer IPs de "Nmap scan report for ...").

    Esta es la pieza central para depurar: en vez de que un subprocess
    tarde minutos "en silencio" (capture_output=True) o revientes sin
    saber en que paso exacto fallo, aqui se ve CADA linea segun llega, y
    ademas se imprime el comando exacto y el codigo de salida al terminar.
    """
    log_message(f"[{label}] Comando: {' '.join(cmd)}")
    output_lines = []
    try:
        process = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1
        )
        for line in process.stdout:
            print(line, end="", flush=True)
            output_lines.append(line)
        process.wait()
        log_message(f"[{label}] Terminado (codigo de salida: {process.returncode})")
        return process.returncode, "".join(output_lines)
    except FileNotFoundError as e:
        log_message(f"[{label}] Comando no encontrado: {e}", "ERROR")
        return -1, ""
    except Exception as e:
        log_message(f"[{label}] Error inesperado al ejecutar el comando: {e}", "ERROR")
        return -1, ""

def install_nmap():
    """Verifica e instala nmap si es necesario."""
    log_message("Comprobando si nmap esta instalado...")
    try:
        result = subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        primera_linea = result.stdout.splitlines()[0] if result.stdout else "(sin version)"
        log_message(f"Nmap ya esta instalado: {primera_linea}")
    except FileNotFoundError:
        log_message("Nmap no esta instalado. Instalando...", "WARNING")
        code, _ = run_streaming(["apt-get", "update"], "apt-get update")
        if code != 0:
            log_message("Fallo 'apt-get update', abortando instalacion de nmap.", "ERROR")
            sys.exit(1)
        code, _ = run_streaming(["apt-get", "install", "-y", "nmap"], "apt-get install nmap")
        if code != 0:
            log_message("Fallo 'apt-get install nmap', abortando.", "ERROR")
            sys.exit(1)
        log_message("Nmap instalado correctamente.")

def is_gateway_ip(ip):
    """Devuelve True si la IP es un gateway de Docker (.1)."""
    return ip.endswith(".1")

def discover_hosts(subnet):
    """Descubre hosts activos en una subred, excluyendo el gateway (.1) y el atacante."""
    log_message(f"=== FASE: descubrimiento de hosts en {subnet} ===")
    code, full_output = run_streaming(["nmap", "-sn", subnet], f"discover:{subnet}")

    if code != 0:
        log_message(f"El descubrimiento en {subnet} termino con error (codigo {code}).", "ERROR")
        return []

    active_hosts = []
    for line in full_output.split("\n"):
        if "Nmap scan report for" in line:
            ip = line.split("for")[1].split("(")[-1].rstrip(")").strip()
            if is_gateway_ip(ip):
                log_message(f"  -> {ip} descartado (gateway de Docker)")
                continue
            if ip == ATTACKER_IP:
                log_message(f"  -> {ip} descartado (soy yo mismo)")
                continue
            log_message(f"  -> host activo encontrado: {ip}")
            active_hosts.append(ip)

    log_message(f"Hosts activos en {subnet}: {active_hosts}")
    return active_hosts

def scan_ports(host, output_dir, index=None, total=None):
    """Escanea puertos abiertos en un host en dos fases: rapida y exhaustiva."""
    progreso = f"[{index}/{total}] " if index and total else ""
    log_message(f"=== FASE: escaneo de puertos {progreso}sobre {host} ===")
    os.makedirs(output_dir, exist_ok=True)
    fast_scan_file = os.path.join(output_dir, f"fast_scan_{host.replace('.', '_')}.txt")
    fast_cmd = ["nmap"] + NMAP_FAST_ARGS + ["-oN", fast_scan_file, host]

    code, _ = run_streaming(fast_cmd, f"fast-scan:{host}")
    if code != 0:
        log_message(f"Escaneo rapido de {host} termino con error (codigo {code}).", "ERROR")
        return False
    log_message(f"Resultado del escaneo rapido guardado en: {fast_scan_file}")

    # Verificar si hay puertos abiertos en el escaneo rapido
    try:
        with open(fast_scan_file, "r") as f:
            contenido = f.read()
        if OPEN_PORT_LINE.search(contenido):
            log_message(f"Puertos abiertos detectados en {host}: lanzando escaneo exhaustivo (todos los puertos)...")
            exhaustive_scan_file = os.path.join(output_dir, f"scan_{host.replace('.', '_')}.txt")
            exhaustive_cmd = ["nmap"] + NMAP_EXHAUSTIVE_ARGS + ["-oN", exhaustive_scan_file, host]
            code, _ = run_streaming(exhaustive_cmd, f"exhaustive-scan:{host}")
            if code != 0:
                log_message(f"Escaneo exhaustivo de {host} termino con error (codigo {code}).", "ERROR")
            else:
                log_message(f"Resultado del escaneo exhaustivo guardado en: {exhaustive_scan_file}")
        else:
            log_message(f"Sin puertos abiertos en {host} (dentro del rango rapido); se omite el escaneo exhaustivo.")
    except Exception as e:
        log_message(f"Error al leer el archivo de escaneo rapido: {e}", "ERROR")

    return True

def scan_vulnerabilities(host, output_dir, enable_vuln_scan=True):
    """Escanea vulnerabilidades en puertos criticos de un host (opcional)."""
    if not enable_vuln_scan:
        log_message(f"Escaneo de vulnerabilidades desactivado para {host} (enable_vuln_scan=False).")
        return

    log_message(f"=== FASE: escaneo de vulnerabilidades sobre {host} ===")
    for port in CRITICAL_PORTS:
        vuln_output = os.path.join(output_dir, f"vuln_{host.replace('.', '_')}_{port}.txt")
        cmd = ["nmap", "--script", "vuln", "-p", port, "-oN", vuln_output, host]
        code, _ = run_streaming(cmd, f"vuln:{host}:{port}")
        if code == 0:
            log_message(f"Vulnerabilidades en {host}:{port} guardadas en {vuln_output}")
        else:
            log_message(f"Escaneo de vulnerabilidades en {host}:{port} termino con error (codigo {code}).", "ERROR")

def main():
    try:
        log_message("########## INICIO DE full_scan.py ##########")

        # Crear directorio de salida
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        log_message(f"Directorio de resultados: {os.path.abspath(OUTPUT_DIR)}")

        # Instalar nmap
        install_nmap()

        # Descubrir hosts activos
        all_hosts = []
        for subnet in SUBNETS:
            hosts = discover_hosts(subnet)
            all_hosts.extend(hosts)

        if not all_hosts:
            log_message("No se encontraron hosts activos. Verifica la conectividad.", "ERROR")
            return

        log_message(f"Hosts activos encontrados en total: {all_hosts} ({len(all_hosts)} hosts)")

        # Escanear puertos abiertos en cada host
        total = len(all_hosts)
        for i, host in enumerate(all_hosts, start=1):
            scan_ports(host, OUTPUT_DIR, index=i, total=total)

        # Escanear vulnerabilidades (opcional)
        scan_vulnerabilities(all_hosts[0], OUTPUT_DIR, enable_vuln_scan=False)  # Solo en el primer host para demo

        log_message("Escaneo completado. Resultados guardados en: " + OUTPUT_DIR)
        log_message("########## FIN DE full_scan.py ##########")

    except KeyboardInterrupt:
        log_message("Escaneo interrumpido manualmente.", "WARNING")
    except Exception as e:
        log_message(f"Error inesperado: {e}", "ERROR")

if __name__ == "__main__":
    main()
