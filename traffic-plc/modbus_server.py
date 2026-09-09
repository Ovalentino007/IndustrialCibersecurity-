#!/usr/bin/env python3
"""
Simulador de PLC industrial con protocolo Modbus TCP
Proceso físico con inercia + lógica de control (BPCS) + lógica de
seguridad independiente (SIS)
Acceso al datastore serializado mediante un RLock compartido para evitar
condiciones de carrera (lost updates) entre los hilos de aplicación y el
hilo interno del servidor Modbus TCP.
"""

import threading
import time
import random
import logging
import signal
import sys

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusSlaveContext,
    ModbusServerContext,
)
from pymodbus.device import ModbusDeviceIdentification

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PLC] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

N_LINES = 5

PRESSURE_HIGH_TARGET = [650, 600, 680, 620, 640]
PRESSURE_LOW_TARGET  = [200, 180, 220, 190, 210]
FLOW_OPEN_TARGET     = [550, 500, 600, 480, 560]
FLOW_CLOSED_TARGET   = [20, 15, 25, 10, 20]
TEMP_HOT_TARGET      = [550, 600, 580, 560, 590]
TEMP_COOL_TARGET     = [350, 370, 360, 340, 355]

NOISE_PRESSURE = 8
NOISE_FLOW = 6
NOISE_TEMP = 5

INERTIA_K = 0.15
UPDATE_INTERVAL = 1.0

CONTROL_CYCLE_TICKS = 3
PRESSURE_SETPOINT_HIGH = 550
PRESSURE_SETPOINT_LOW = 350
TEMP_COOLING_ON = 520
TEMP_COOLING_OFF = 420

PRESSURE_SAFETY_LIMIT = 700


class ThreadSafeModbusSlaveContext(ModbusSlaveContext):
    """ModbusSlaveContext que serializa el acceso al datastore mediante un
    RLock compartido. Esto evita:
      (a) que el hilo interno del servidor Modbus TCP (que atiende
          peticiones de SCADA/workstation/atacante) se solape con los
          hilos de proceso/control/seguridad, y
      (b) que dos hilos de aplicación pierdan una actualización del otro
          (lost update) al leer-calcular-escribir sobre el mismo rango
          de registros/coils (p.ej. BPCS y SIS escribiendo válvulas).

    Se usa RLock (reentrante) y no Lock porque los propios hilos de
    aplicación también envuelven su bloque leo-calculo-escribo completo
    con este mismo lock (ver los bucles más abajo); con un Lock normal
    esto causaría un auto-deadlock al intentar readquirirlo desde el
    mismo hilo que ya lo tiene.
    """

    def __init__(self, *args, lock=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._data_lock = lock or threading.RLock()

    def getValues(self, fx, address, count=1):
        with self._data_lock:
            return super().getValues(fx, address, count)

    def setValues(self, fx, address, values):
        with self._data_lock:
            return super().setValues(fx, address, values)


def clamp(value, lo, hi):
    return max(lo, min(hi, value))


def approach(current, target, noise_amplitude):
    next_value = current + INERTIA_K * (target - current)
    next_value += random.uniform(-noise_amplitude, noise_amplitude)
    return next_value


def physical_process_loop(store, stop_event, lock):
    logger.info("Hilo de proceso físico iniciado")
    pressures = list(PRESSURE_LOW_TARGET)
    flows = list(FLOW_CLOSED_TARGET)
    temps = list(TEMP_COOL_TARGET)

    while not stop_event.is_set():
        try:
            with lock:
                valves = store.getValues(1, 0, count=5)
                pumps = store.getValues(1, 5, count=2)

                for i in range(N_LINES):
                    valve_open = bool(valves[i])
                    pump_on = bool(pumps[0]) if i < 3 else bool(pumps[1])

                    p_target = PRESSURE_LOW_TARGET[i] if valve_open else PRESSURE_HIGH_TARGET[i]
                    f_target = FLOW_OPEN_TARGET[i] if valve_open else FLOW_CLOSED_TARGET[i]
                    t_target = TEMP_COOL_TARGET[i] if pump_on else TEMP_HOT_TARGET[i]
                    if not valve_open:
                        t_target += 30

                    pressures[i] = clamp(approach(pressures[i], p_target, NOISE_PRESSURE), 50, 900)
                    flows[i] = clamp(approach(flows[i], f_target, NOISE_FLOW), 0, 1000)
                    temps[i] = clamp(approach(temps[i], t_target, NOISE_TEMP), 100, 1000)

                store.setValues(3, 0, [int(t) for t in temps] +
                                        [int(p) for p in pressures] +
                                        [int(f) for f in flows])

            if int(time.time()) % 10 == 0:
                logger.info(
                    f"P: {[round(p/100,1) for p in pressures]}  "
                    f"T: {[round(t/10,1) for t in temps]}  "
                    f"F: {[round(f/10,1) for f in flows]}"
                )
        except Exception as e:
            logger.error(f"Error en el hilo de proceso físico: {e}")

        time.sleep(UPDATE_INTERVAL)


def control_logic_loop(store, stop_event, lock):
    logger.info("Hilo de control (BPCS) iniciado")
    tick = 0

    while not stop_event.is_set():
        try:
            if tick % CONTROL_CYCLE_TICKS == 0:
                with lock:
                    pressures = store.getValues(3, 5, count=5)
                    temps = store.getValues(3, 0, count=5)
                    valves = list(store.getValues(1, 0, count=5))
                    pumps = list(store.getValues(1, 5, count=2))

                    for i in range(N_LINES):
                        if pressures[i] > PRESSURE_SETPOINT_HIGH:
                            valves[i] = True
                        elif pressures[i] < PRESSURE_SETPOINT_LOW:
                            valves[i] = False

                    for group, (lo, hi) in enumerate([(0, 3), (3, 5)]):
                        avg_temp = sum(temps[lo:hi]) / (hi - lo)
                        if pumps[group]:
                            pumps[group] = avg_temp > TEMP_COOLING_OFF
                        else:
                            pumps[group] = avg_temp > TEMP_COOLING_ON

                    store.setValues(1, 0, [bool(v) for v in valves])
                    store.setValues(1, 5, [bool(p) for p in pumps])

            tick += 1
        except Exception as e:
            logger.error(f"Error en el hilo de control BPCS: {e}")

        time.sleep(UPDATE_INTERVAL)


def safety_logic_loop(store, stop_event, lock):
    logger.info("Hilo de seguridad (SIS) iniciado")

    while not stop_event.is_set():
        try:
            with lock:
                pressures = store.getValues(3, 5, count=5)
                valves = list(store.getValues(1, 0, count=5))
                tripped = False

                for i in range(N_LINES):
                    if pressures[i] > PRESSURE_SAFETY_LIMIT and not valves[i]:
                        valves[i] = True
                        tripped = True
                        logger.warning(
                            f"[SIS] ¡Disparo de seguridad en línea {i}! "
                            f"Presión={pressures[i]/100:.1f} bar > límite "
                            f"{PRESSURE_SAFETY_LIMIT/100:.1f} bar. Válvula forzada a ABIERTA."
                        )

                if tripped:
                    store.setValues(1, 0, [bool(v) for v in valves])

        except Exception as e:
            logger.error(f"Error en el hilo de seguridad SIS: {e}")

        time.sleep(0.5)


def main():
    logger.info("=" * 60)
    logger.info("  PLC Simulator v2 - Proceso físico + BPCS + SIS")
    logger.info("  Escuchando en 0.0.0.0:5020 (Slave ID: 1)")
    logger.info("=" * 60)

    init_hr = list(TEMP_COOL_TARGET) + list(PRESSURE_LOW_TARGET) + list(FLOW_CLOSED_TARGET) + [350, 1] + [0] * 83
    init_coils = [False] * 7 + [False] * 93

    process_lock = threading.RLock()

    store = ThreadSafeModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, init_coils),
        hr=ModbusSequentialDataBlock(0, init_hr),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
        zero_mode=True,
        lock=process_lock,
    )
    context = ModbusServerContext(slaves={0x01: store}, single=False)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "TFG-IDS-Industrial"
    identity.ProductCode = "PLC-SIM-v2"
    identity.ProductName = "Industrial PLC Simulator (physical process + BPCS + SIS)"
    identity.ModelName = "PLC-SIM-Modbus"
    identity.MajorMinorRevision = "2.0.0"

    stop_event = threading.Event()

    threads = [
        threading.Thread(target=physical_process_loop, args=(store, stop_event, process_lock), daemon=True, name="PhysicalProcess"),
        threading.Thread(target=control_logic_loop, args=(store, stop_event, process_lock), daemon=True, name="BPCS"),
        threading.Thread(target=safety_logic_loop, args=(store, stop_event, process_lock), daemon=True, name="SIS"),
    ]
    for t in threads:
        t.start()

    def shutdown(sig, frame):
        logger.info("Apagando servidor PLC...")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Servidor Modbus TCP iniciado. Esperando conexiones...")
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", 5020))


if __name__ == "__main__":
    main()