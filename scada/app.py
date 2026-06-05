#!/usr/bin/env python3
"""
Servidor SCADA/HMI
==================
Dashboard web en tiempo real que:
  - Lee datos del PLC via Modbus TCP cada 2s
  - Expone API REST /api/data para el frontend
  - Genera tráfico benigno continuo hacia el PLC
  - Almacena histórico en memoria (últimos 100 valores)
"""

import os
import time
import threading
import logging
from collections import deque
from datetime import datetime

from flask import Flask, jsonify, render_template
from pymodbus.client import ModbusTcpClient

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SCADA] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

PLC_HOST = os.getenv("PLC_HOST", "192.168.100.10")
PLC_PORT = int(os.getenv("PLC_PORT", 5020))
POLL_INTERVAL = 2.0   # segundos
HISTORY_SIZE  = 100   # puntos en el histórico

# Estado compartido (protegido por lock)
state_lock = threading.Lock()
current_data = {
    "timestamp": None,
    "temperatures": [0.0] * 5,
    "pressures":    [0.0] * 5,
    "flows":        [0.0] * 5,
    "valves":       [False] * 5,
    "pumps":        [False] * 2,
    "status":       "iniciando",
    "poll_count":   0,
    "error_count":  0,
}
history = deque(maxlen=HISTORY_SIZE)


def poll_plc():
    """Hilo de polling continuo al PLC."""
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=3)
    logger.info(f"Conectando a PLC en {PLC_HOST}:{PLC_PORT}...")

    while True:
        try:
            if not client.is_socket_open():
                client.connect()

            # Leer 17 holding registers (temps + presiones + caudales + setpoint)
            hr = client.read_holding_registers(0, 17, slave=1)
            # Leer 7 coils (válvulas + bombas)
            co = client.read_coils(0, 7, slave=1)

            if hr.isError() or co.isError():
                raise ValueError("Error en respuesta Modbus")

            regs  = hr.registers
            coils = co.bits

            snapshot = {
                "timestamp":    datetime.utcnow().isoformat() + "Z",
                "temperatures": [round(regs[i] / 10, 1) for i in range(5)],
                "pressures":    [round(regs[i+5] / 100, 2) for i in range(5)],
                "flows":        [round(regs[i+10] / 10, 1) for i in range(5)],
                "valves":       [bool(coils[i]) for i in range(5)],
                "pumps":        [bool(coils[5]), bool(coils[6])],
                "status":       "connected",
            }

            with state_lock:
                current_data.update(snapshot)
                current_data["poll_count"] += 1
                history.append({
                    "t":    snapshot["timestamp"],
                    "temp": snapshot["temperatures"][0],
                    "pres": snapshot["pressures"][0],
                    "flow": snapshot["flows"][0],
                })

        except Exception as e:
            logger.warning(f"Error polling PLC: {e}")
            with state_lock:
                current_data["status"] = f"error: {e}"
                current_data["error_count"] += 1
            client.close()

        time.sleep(POLL_INTERVAL)


# ── Rutas Flask ───────────────────────────────────────────────

@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/api/data")
def api_data():
    with state_lock:
        return jsonify(current_data)


@app.route("/api/history")
def api_history():
    with state_lock:
        return jsonify(list(history))


@app.route("/api/status")
def api_status():
    with state_lock:
        return jsonify({
            "status":      current_data["status"],
            "poll_count":  current_data["poll_count"],
            "error_count": current_data["error_count"],
            "plc":         f"{PLC_HOST}:{PLC_PORT}",
        })


if __name__ == "__main__":
    # Arrancar hilo de polling
    t = threading.Thread(target=poll_plc, daemon=True, name="PLCPoller")
    t.start()

    logger.info("Servidor SCADA iniciado en 0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
