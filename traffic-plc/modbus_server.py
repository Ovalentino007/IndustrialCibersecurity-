#!/usr/bin/env python3
"""
Simulador de PLC industrial con protocolo Modbus TCP (Fijado para Pymodbus 3.x)
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

# ── Parámetros de simulación ──────────────────────────────────
TEMP_BASE    = [350, 420, 510, 280, 390]   # °C × 10
PRESS_BASE   = [200, 350, 150, 480, 310]   # bar × 100
FLOW_BASE    = [450, 320, 600, 180, 510]   # L/min × 10
NOISE_TEMP   = 15
NOISE_PRESS  = 20
NOISE_FLOW   = 30
UPDATE_INTERVAL = 1.0


def update_process(store, stop_event):
    """
    Pasamos 'store' directamente (ModbusSlaveContext). 
    Así evitamos usar métodos malditos de 'context' que cambian entre versiones.
    """
    logger.info("Hilo de simulación iniciado")
    tick = 0

    while not stop_event.is_set():
        try:
            # Temperatura: deriva lenta + ruido
            temps = [
                max(100, min(1000, TEMP_BASE[i]
                    + random.randint(-NOISE_TEMP, NOISE_TEMP)
                    + int(5 * (tick % 60 - 30) / 30)))
                for i in range(5)
            ]

            # Presión: ruido
            pressures = [
                max(50, min(700, PRESS_BASE[i]
                    + random.randint(-NOISE_PRESS, NOISE_PRESS)))
                for i in range(5)
            ]

            # Caudal: Leer estado de bobinas (fx 1)
            coils = store.getValues(1, 0, count=7)
            flows = [
                max(0, min(1000, FLOW_BASE[i]
                    + random.randint(-NOISE_FLOW, NOISE_FLOW)
                    + (200 if coils[i] else -200)))
                for i in range(5)
            ]

            # Escribir en holding registers (fx 3)
            store.setValues(3, 0, temps + pressures + flows)

            # Cada 30 segundos cambiar estado de válvulas aleatoriamente
            if tick % 30 == 0:
                new_coils = [random.choice([True, False]) for _ in range(7)]
                store.setValues(1, 0, new_coils)
                logger.info(
                    f"Estado válvulas: {['A' if v else 'C' for v in new_coils[:5]]} "
                    f"Bombas: {['M' if new_coils[5] else 'P']} {['M' if new_coils[6] else 'P']}"
                )

            # Log periódico de valores
            if tick % 10 == 0:
                logger.info(
                    f"T(°C): {[t/10 for t in temps[:3]]} ... "
                    f"P(bar): {[p/100 for p in pressures[:3]]} ..."
                )

            tick += 1
        except Exception as e:
            logger.error(f"Error en el hilo de simulación: {e}")
            
        time.sleep(UPDATE_INTERVAL)


def main():
    logger.info("=" * 50)
    logger.info("  PLC Simulator - Modbus TCP")
    logger.info("  Escuchando en 0.0.0.0:5020 (Slave ID: 1)")
    logger.info("=" * 50)

    # 1. Valores iniciales
    init_hr = TEMP_BASE + PRESS_BASE + FLOW_BASE + [350, 1] + [0] * 83
    init_coils = [True, False, True, False, True, True, False] + [False] * 93

    # 2. Construir el bloque de datos base
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, init_coils),
        hr=ModbusSequentialDataBlock(0, init_hr),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
        zero_mode=True
    )
    
    # 3. El contexto global DEBE recibir el almacén indexado por el ID de esclavo (1)
    # IMPORTANTE: single=False para que valide correctamente el esclavo 1 que pide el SCADA
    context = ModbusServerContext(slaves={0x01: store}, single=False)

    # Identificación del dispositivo
    identity = ModbusDeviceIdentification()
    identity.VendorName    = "TFG-IDS-Industrial"
    identity.ProductCode   = "PLC-SIM-v1"
    identity.VendorUrl     = "http://192.168.100.10"
    identity.ProductName   = "Industrial PLC Simulator"
    identity.ModelName     = "PLC-SIM-Modbus"
    identity.MajorMinorRevision = "1.0.0"

    stop_event = threading.Event()

    # 4. PASAMOS 'store' DIRECTAMENTE EN LUGAR DE 'context'
    sim_thread = threading.Thread(
        target=update_process,
        args=(store, stop_event),
        daemon=True,
        name="ProcessSimulator",
    )
    sim_thread.start()

    def shutdown(sig, frame):
        logger.info("Apagando servidor PLC...")
        stop_event.set()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    logger.info("Servidor Modbus TCP iniciado. Esperando conexiones...")
    
    # Arrancar el servidor nativo de Pymodbus v3
    StartTcpServer(
        context=context,
        identity=identity,
        address=("0.0.0.0", 5020),
    )


if __name__ == "__main__":
    main()