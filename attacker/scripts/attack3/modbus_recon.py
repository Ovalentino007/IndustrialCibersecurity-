#!/usr/bin/env python3
"""
Ataque 3, Fase 0: reconocimiento pasivo/estadistico del mapa de registros
Modbus del PLC, SIN conocimiento previo de que direccion es el setpoint
ni cuales son las valvulas.

Justificacion (para la memoria): Modbus no lleva ningun metadato semantico
-- a diferencia de otros protocolos ICS, las direcciones son numeros sin
nombre ni tipo declarado. Un atacante real no parte con un mapa de
registros en la mano; tiene que reconstruirlo. Los caminos documentados en
incidentes reales son reconocimiento pasivo (esnifar trafico legitimo
SCADA<->PLC y correlacionar patrones), reconocimiento activo (leer todo el
espacio de direcciones y observar como evoluciona cada una), o robo de los
ficheros de proyecto de la estacion de ingenieria (Stuxnet, TRITON). Este
script implementa la segunda via: lee TODO el rango de holding registers y
coils repetidamente durante una ventana de observacion, y clasifica cada
direccion por como se comporta su valor a lo largo del tiempo -- exactamente
el tipo de huella estadistica que herramientas reales de reconocimiento
ICS (p.ej. plcscan) usan para distinguir sensores de puntos de control.

Salida: un fichero recon_manifest.json con la clasificacion completa y la
mejor conjetura de que direccion es el setpoint y que coils de valvula
parecen tener actividad de control. modbus_write_attack.py puede leer este
manifiesto para no depender de direcciones conocidas de antemano.
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

# Rango de direcciones a escanear. 0-99 es una convencion habitual en
# herramientas de escaneo Modbus (p.ej. el rango por defecto de plcscan/
# smod); en este laboratorio coincide con el tamano real del datastore
# configurado en modbus_server.py, pero el escaneo no depende de conocer
# ese dato de antemano -- si el PLC tuviera menos direcciones validas, las
# lecturas fuera de rango simplemente devolverian una excepcion Modbus
# ILLEGAL_DATA_ADDRESS, que este script tambien maneja.
SCAN_COUNT = 100

OBSERVATION_WINDOW_S = 65       # > que el intervalo maximo de escritura legitima (45-90s, ver scada/app.py)
SAMPLE_INTERVAL_S = 1.0         # igual que el ciclo del proceso fisico real (ver modbus_server.py)

# Umbrales de clasificacion (heuristica estadistica, no conocimiento previo
# del significado real de cada registro).
SENSOR_MIN_DISTINCT_VALUES = 5   # un sensor con ruido cambia casi cada muestra
STATIC_NONTRIVIAL_MIN_VALUE = 10 # para distinguir un setpoint (cientos) de un flag (0/1)

MANIFEST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recon_manifest.json")


def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)


def connect():
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=3)
    if not client.connect():
        log_message(f"No se pudo conectar al PLC en {PLC_HOST}:{PLC_PORT}", "ERROR")
        sys.exit(1)
    return client


def collect_samples(client):
    """Lee todo el rango de holding registers y coils cada
    SAMPLE_INTERVAL_S durante OBSERVATION_WINDOW_S, y devuelve el
    historial de valores observado por direccion."""
    hr_history = {addr: [] for addr in range(SCAN_COUNT)}
    coil_history = {addr: [] for addr in range(SCAN_COUNT)}

    log_message(
        f"Iniciando reconocimiento pasivo/activo: leyendo {SCAN_COUNT} holding "
        f"registers y {SCAN_COUNT} coils cada {SAMPLE_INTERVAL_S}s durante "
        f"{OBSERVATION_WINDOW_S}s (sin asumir de antemano que direccion es que)."
    )

    start = time.time()
    sample_count = 0
    while time.time() - start < OBSERVATION_WINDOW_S:
        hr = client.read_holding_registers(0, count=SCAN_COUNT, slave=SLAVE_ID)
        co = client.read_coils(0, count=SCAN_COUNT, slave=SLAVE_ID)

        if not hr.isError():
            for addr, value in enumerate(hr.registers):
                hr_history[addr].append(value)
        else:
            log_message(f"Excepcion Modbus leyendo holding registers: {hr}", "WARNING")

        if not co.isError():
            for addr, value in enumerate(co.bits[:SCAN_COUNT]):
                coil_history[addr].append(bool(value))
        else:
            log_message(f"Excepcion Modbus leyendo coils: {co}", "WARNING")

        sample_count += 1
        if sample_count % 15 == 0:
            log_message(f"  ... {sample_count} muestras recogidas ({int(time.time() - start)}s transcurridos)")

        time.sleep(SAMPLE_INTERVAL_S)

    log_message(f"Reconocimiento completado: {sample_count} muestras por direccion.")
    return hr_history, coil_history


def classify_holding_registers(hr_history):
    """Clasifica cada holding register segun como varia su valor en la
    ventana de observacion, SIN conocer su significado real."""
    classification = {}
    for addr, values in hr_history.items():
        if not values:
            classification[addr] = {"role": "sin_datos"}
            continue

        distinct = sorted(set(values))
        vmin, vmax = min(values), max(values)

        if len(distinct) == 1:
            if values[0] == 0:
                role = "constante_cero_probable_no_usado"
            elif values[0] < STATIC_NONTRIVIAL_MIN_VALUE:
                role = "constante_pequena_candidato_flag_modo"
            else:
                role = "constante_no_trivial_candidato_setpoint"
            classification[addr] = {
                "role": role,
                "constant_value": values[0],
            }
        elif len(distinct) >= SENSOR_MIN_DISTINCT_VALUES:
            classification[addr] = {
                "role": "variable_continua_candidato_sensor",
                "min": vmin,
                "max": vmax,
                "distinct_values_seen": len(distinct),
            }
        else:
            # Cambia, pero pocas veces y/o pocos valores distintos --
            # exactamente el patron esperado de un setpoint que un
            # operador ajusta cada 45-90s (uno o dos saltos durante la
            # ventana de observacion, no ruido continuo).
            classification[addr] = {
                "role": "variable_discreta_candidato_setpoint",
                "min": vmin,
                "max": vmax,
                "distinct_values_seen": len(distinct),
                "values_seen": distinct,
            }
    return classification


def classify_coils(coil_history):
    """Clasifica cada coil segun si se observo actividad (toggle) durante
    la ventana de observacion."""
    classification = {}
    for addr, values in coil_history.items():
        if not values:
            classification[addr] = {"role": "sin_datos"}
            continue

        distinct = set(values)
        if len(distinct) > 1:
            classification[addr] = {"role": "control_candidato_con_actividad_observada"}
        elif values[0]:
            classification[addr] = {"role": "constante_activo_sin_cambios_en_la_ventana"}
        else:
            classification[addr] = {"role": "constante_inactivo_sin_cambios_en_la_ventana"}
    return classification


def build_best_guesses(hr_classification, coil_classification):
    """A partir de la clasificacion, propone la mejor conjetura de
    direccion de setpoint y de coils de valvula con actividad."""
    setpoint_candidates = [
        addr for addr, info in hr_classification.items()
        if info.get("role") in ("constante_no_trivial_candidato_setpoint", "variable_discreta_candidato_setpoint")
    ]
    # Preferimos el candidato "discreto" (se vio cambiar durante la
    # ventana) sobre el "constante" (no se vio cambiar, pero el valor no
    # es trivial) -- el primero es una senal mas fuerte de que es un
    # punto de escritura activo, no solo un registro con un valor de
    # fabrica no nulo.
    discrete_candidates = [
        addr for addr, info in hr_classification.items()
        if info.get("role") == "variable_discreta_candidato_setpoint"
    ]
    best_setpoint = discrete_candidates[0] if discrete_candidates else (
        setpoint_candidates[0] if setpoint_candidates else None
    )

    active_coils = sorted([
        addr for addr, info in coil_classification.items()
        if info.get("role") == "control_candidato_con_actividad_observada"
    ])

    return best_setpoint, active_coils


def main():
    log_message("########## INICIO Fase 0 (reconocimiento Modbus) del ataque 3 ##########")
    client = connect()

    try:
        hr_history, coil_history = collect_samples(client)
    finally:
        client.close()

    hr_classification = classify_holding_registers(hr_history)
    coil_classification = classify_coils(coil_history)
    best_setpoint, active_coils = build_best_guesses(hr_classification, coil_classification)

    log_message("=== Resultado del reconocimiento ===")
    for addr, info in hr_classification.items():
        if info.get("role") not in ("constante_cero_probable_no_usado", "sin_datos"):
            log_message(f"  HR[{addr}]: {info}")
    for addr, info in coil_classification.items():
        if info.get("role") != "sin_datos":
            log_message(f"  Coil[{addr}]: {info}")

    if best_setpoint is not None:
        log_message(f"Mejor conjetura de direccion de SETPOINT: {best_setpoint}", "SUCCESS")
    else:
        log_message("No se identifico ningun candidato claro a setpoint en esta ventana.", "WARNING")

    if active_coils:
        log_message(f"Coils con actividad de control observada (candidatos a valvulas/bombas): {active_coils}", "SUCCESS")
    else:
        log_message(
            "No se observo actividad en ningun coil durante la ventana "
            "(el BPCS puede no haber necesitado cambiar ninguna valvula/bomba "
            "en este intervalo concreto; probar con una ventana mas larga).",
            "WARNING",
        )

    manifest = {
        "target": f"{PLC_HOST}:{PLC_PORT}",
        "scan_duration_s": OBSERVATION_WINDOW_S,
        "sample_interval_s": SAMPLE_INTERVAL_S,
        "holding_registers": {str(a): i for a, i in hr_classification.items()},
        "coils": {str(a): i for a, i in coil_classification.items()},
        "best_guess_setpoint_address": best_setpoint,
        "best_guess_active_coil_addresses": active_coils,
    }
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
    log_message(f"Manifiesto de reconocimiento guardado en: {MANIFEST_PATH}")

    log_message("########## FIN Fase 0 (reconocimiento Modbus) ##########")


if __name__ == "__main__":
    main()