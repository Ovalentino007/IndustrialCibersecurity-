#!/usr/bin/env python3

import subprocess
import os
import sys
from datetime import datetime

# --- CONFIGURACIÓN ---
SUBNETS = ["192.168.100.0/24", "192.168.200.0/24"]
OUTPUT_DIR = "/scripts/recon_results"
NMAP_ARGS = ["-p-", "-sV", "--open", "-T4"]  # Escaneo exhaustivo de puertos (1-65535)
CRITICAL_PORTS = ["502", "5020", "80", "8080", "5432", "22", "443"]  # Puertos críticos para escaneo de vulnerabilidades

# --- FUNCIONES ---
def install_nmap():
    """Verifica e instala nmap si es necesario."""
    try:
        subprocess.run(["nmap", "--version"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print("[+] Nmap ya está instalado.")
    except FileNotFoundError:
        print("[!] Nmap no está instalado. Instalando...")
        try:
            subprocess.run(["apt-get", "update"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["apt-get", "install", "-y", "nmap"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("[+] Nmap instalado correctamente.")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error al instalar nmap: {e.stderr.decode()}")
            sys.exit(1)

def is_gateway_ip(ip):
    """Devuelve True si la IP es un gateway de Docker (.1)."""
    return ip.endswith(".1")

def discover_hosts(subnet):
    """Descubre hosts activos en una subred, excluyendo el gateway (.1)."""
    cmd = ["nmap", "-sn", subnet]
    print(f"[*] Escaneando subred {subnet} para descubrir hosts activos...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        active_hosts = []
        for line in result.stdout.split("\n"):
            if "Nmap scan report for" in line:
                # Extrae solo la IP (ignora nombres DNS)
                ip = line.split("for")[1].split("(")[-1].rstrip(")").strip()
                if not is_gateway_ip(ip):  # Excluye el gateway .1
                    active_hosts.append(ip)
        print(f"[+] Hosts activos en {subnet}: {active_hosts}")
        return active_hosts
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al descubrir hosts en {subnet}: {e.stderr.decode()}")
        return []

def scan_ports(host, output_dir):
    """Escanea todos los puertos abiertos de un host y guarda los resultados."""
    output_file = os.path.join(output_dir, f"scan_{host.replace('.', '_')}.txt")
    cmd = ["nmap"] + NMAP_ARGS + ["-oN", output_file, host]
    print(f"[*] Escaneando puertos abiertos en {host}...")
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(result.stdout)
        if result.stderr:
            print(f"[!] Error en escaneo de puertos para {host}: {result.stderr.decode()}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error al escanear puertos de {host}: {e.stderr.decode()}")
        return False

def scan_vulnerabilities(host, output_dir):
    """Escanea vulnerabilidades en puertos críticos de un host."""
    for port in CRITICAL_PORTS:
        vuln_output = os.path.join(output_dir, f"vuln_{host.replace('.', '_')}_{port}.txt")
        cmd = ["nmap", "--script", "vuln", "-p", port, "-oN", vuln_output, host]
        print(f"[*] Escaneando vulnerabilidades en {host}:{port}...")
        try:
            subprocess.run(cmd, check=True)
            print(f"[+] Vulnerabilidades en {host}:{port} guardadas en {vuln_output}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error al escanear vulnerabilidades en {host}:{port}: {e.stderr.decode()}")

def main():
    try:
        # Crear directorio de salida
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        print(f"[+] Directorio de resultados: {OUTPUT_DIR}")

        # Instalar nmap
        install_nmap()

        # Descubrir hosts activos (excluyendo .1)
        all_hosts = []
        for subnet in SUBNETS:
            hosts = discover_hosts(subnet)
            all_hosts.extend(hosts)

        if not all_hosts:
            print("[!] No se encontraron hosts activos. Verifica la conectividad.")
            return

        print(f"\n[+] Hosts activos encontrados (excluyendo gateways .1): {all_hosts}")

        # Escanear puertos abiertos en cada host
        for host in all_hosts:
            scan_ports(host, OUTPUT_DIR)

        # Escanear vulnerabilidades en puertos críticos
        print("\n[*] Iniciando escaneo de vulnerabilidades en puertos críticos...")
        for host in all_hosts:
            scan_vulnerabilities(host, OUTPUT_DIR)

        print("\n[+] Escaneo completado. Resultados guardados en:", OUTPUT_DIR)

    except KeyboardInterrupt:
        print("\n[!] Escaneo interrumpido manualmente.")
    except Exception as e:
        print(f"\n[!] Error inesperado: {e}")

if __name__ == "__main__":
    main()