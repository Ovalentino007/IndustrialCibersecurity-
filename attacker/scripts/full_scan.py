#!/usr/bin/env python3
"""
Script de reconocimiento completo para redes industriales.
Objetivo: Simular un ataque realista de reconocimiento en un entorno ICS.
"""

import subprocess
import os
import sys
from datetime import datetime

# --- CONFIGURACIÓN ---
SUBNETS = ["192.168.100.0/24", "192.168.200.0/24"]
OUTPUT_DIR = "./nmap"  # Ruta relativa dentro de /scripts
NMAP_FAST_ARGS = ["-p", "1-1000,502,5020,80,8080,5432,22,443", "-sV", "--open", "-T3"]  # Escaneo rápido
NMAP_EXHAUSTIVE_ARGS = ["-p-", "-sV", "--open", "-T4"]  # Escaneo exhaustivo (solo si hay puertos abiertos)
CRITICAL_PORTS = ["502", "5020", "80", "8080", "5432", "22", "443"]  # Puertos críticos para escaneo de vulnerabilidades
ATTACKER_IP = "192.168.100.100"  # IP del contenedor attacker_node

# --- FUNCIONES ---
def log_message(message, level="INFO"):
    """Imprime un mensaje con timestamp y nivel de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")

def install_nmap():
    """Verifica e instala nmap si es necesario."""
    try:
        subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_message("Nmap ya está instalado.")
    except FileNotFoundError:
        log_message("Nmap no está instalado. Instalando...", "WARNING")
        try:
            subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["apt-get", "install", "-y", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            log_message("Nmap instalado correctamente.")
        except subprocess.CalledProcessError as e:
            log_message(f"Error al instalar nmap: {e.stderr.decode()}", "ERROR")
            sys.exit(1)

def is_gateway_ip(ip):
    """Devuelve True si la IP es un gateway de Docker (.1)."""
    return ip.endswith(".1")

def discover_hosts(subnet):
    """Descubre hosts activos en una subred, excluyendo el gateway (.1) y el atacante."""
    cmd = ["nmap", "-sn", subnet]
    log_message(f"Escaneando subred {subnet} para descubrir hosts activos...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        active_hosts = []
        for line in result.stdout.split("\n"):
            if "Nmap scan report for" in line:
                ip = line.split("for")[1].split("(")[-1].rstrip(")").strip()
                if not is_gateway_ip(ip) and ip != ATTACKER_IP:  # Excluye gateway y atacante
                    active_hosts.append(ip)
        log_message(f"Hosts activos en {subnet}: {active_hosts}")
        return active_hosts
    except subprocess.CalledProcessError as e:
        log_message(f"Error al descubrir hosts en {subnet}: {e.stderr.decode()}", "ERROR")
        return []

def scan_ports(host, output_dir):
    """Escanea puertos abiertos en un host en dos fases: rápida y exhaustiva."""
    os.makedirs(output_dir, exist_ok=True)
    fast_scan_file = os.path.join(output_dir, f"fast_scan_{host.replace('.', '_')}.txt")
    fast_cmd = ["nmap"] + NMAP_FAST_ARGS + ["-oN", fast_scan_file, host]

    log_message(f"Escaneo rápido de puertos en {host}...")
    try:
        subprocess.run(fast_cmd, check=True)
    except subprocess.CalledProcessError as e:
        log_message(f"Error en escaneo rápido para {host}: {e.stderr.decode()}", "ERROR")
        return False

    # Verificar si hay puertos abiertos en el escaneo rápido
    try:
        with open(fast_scan_file, "r") as f:
            if "open" in f.read():
                exhaustive_scan_file = os.path.join(output_dir, f"scan_{host.replace('.', '_')}.txt")
                exhaustive_cmd = ["nmap"] + NMAP_EXHAUSTIVE_ARGS + ["-oN", exhaustive_scan_file, host]
                log_message(f"Escaneo exhaustivo de puertos en {host} (se encontraron puertos abiertos)...")
                subprocess.run(exhaustive_cmd, check=True)
    except Exception as e:
        log_message(f"Error al leer el archivo de escaneo rápido: {e}", "ERROR")

    return True

def scan_vulnerabilities(host, output_dir, enable_vuln_scan=True):
    """Escanea vulnerabilidades en puertos críticos de un host (opcional)."""
    if not enable_vuln_scan:
        return

    for port in CRITICAL_PORTS:
        vuln_output = os.path.join(output_dir, f"vuln_{host.replace('.', '_')}_{port}.txt")
        cmd = ["nmap", "--script", "vuln", "-p", port, "-oN", vuln_output, host]
        log_message(f"Escaneando vulnerabilidades en {host}:{port}...")
        try:
            subprocess.run(cmd, check=True)
            log_message(f"Vulnerabilidades en {host}:{port} guardadas en {vuln_output}")
        except subprocess.CalledProcessError as e:
            log_message(f"Error al escanear vulnerabilidades en {host}:{port}: {e.stderr.decode()}", "ERROR")

def main():
    try:
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

        log_message(f"Hosts activos encontrados: {all_hosts}")

        # Escanear puertos abiertos en cada host
        for host in all_hosts:
            scan_ports(host, OUTPUT_DIR)

        # Escanear vulnerabilidades (opcional)
        scan_vulnerabilities(all_hosts[0], OUTPUT_DIR, enable_vuln_scan=False)  # Solo en el primer host para demo

        log_message("Escaneo completado. Resultados guardados en: " + OUTPUT_DIR)

    except KeyboardInterrupt:
        log_message("Escaneo interrumpido manualmente.", "WARNING")
    except Exception as e:
        log_message(f"Error inesperado: {e}", "ERROR")

if __name__ == "__main__":
    main()
