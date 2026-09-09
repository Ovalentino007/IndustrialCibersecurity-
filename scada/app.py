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
import random
import os
import time
import threading
import logging
import psycopg2
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

PLC_HOST = os.getenv("PLC_HOST", "192.168.200.3")
PLC_PORT = int(os.getenv("PLC_PORT", 5020))
POLL_INTERVAL = 2.0   # segundos
HISTORY_SIZE  = 100   # puntos en el histórico

DB_HOST = "192.168.202.3"
DB_NAME = "industrial_data"
DB_USER = "scada_tfg"
DB_PASSWORD = "scada_pass_tfg"

# Estado compartido (protegido por lock)
state_lock = threading.Lock()
current_data = {
    "timestamp": None,
    "temperatures": [0.0] * 5,
    "pressures":    [0.0] * 5,
    "flows":        [0.0] * 5,
    "valves":       [False] * 5,
    "pumps":        [False] * 2,
    "setpoint":     0.0,
    "status":       "iniciando",
    "poll_count":   0,
    "error_count":  0,
}
history = deque(maxlen=HISTORY_SIZE)

def get_db_connection():
    try:
        conn = psycopg2.connect(
            host = DB_HOST,
            database = DB_NAME,
            user = DB_USER,
            password = DB_PASSWORD
        )
        logger.info(f"Conexion a PostgreSQL establecida con {DB_HOST}")
        return conn
    except Exception as e:
        logger.error(f"Error al conector con PostgreSQL: {e}")
        return None
    
def init_db():
    conn = get_db_connection()
    if conn:
        try:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS plc_data (
                    id SERIAL PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT NOW(),
                    temperature_1 FLOAT,
                    temperature_2 FLOAT,
                    temperature_3 FLOAT,
                    temperature_4 FLOAT,
                    temperature_5 FLOAT,
                    pressure_1 FLOAT,
                    pressure_2 FLOAT,
                    pressure_3 FLOAT,
                    pressure_4 FLOAT,
                    pressure_5 FLOAT,
                    flow_1 FLOAT,
                    flow_2 FLOAT,
                    flow_3 FLOAT,
                    flow_4 FLOAT,
                    flow_5 FLOAT,
                    valve_1 BOOLEAN,
                    valve_2 BOOLEAN,
                    valve_3 BOOLEAN,
                    valve_4 BOOLEAN,
                    valve_5 BOOLEAN,
                    pump_1 BOOLEAN,
                    pump_2 BOOLEAN           
                );
            """)
            conn.commit()
            logger.info("Tabla 'plc_data' inicializada correctamente en PostgreSQL")
        except Exception as e:
            logger.error(f"Error al inicializar la tabla: {e}")
        finally:
            conn.close()

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
                "setpoint":     round(regs[15] / 100, 2),
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
            
            conn = get_db_connection()
            if conn:
                try:
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO plc_data (
                            timestamp, temperature_1, temperature_2,
                            temperature_3, temperature_4, temperature_5,
                            pressure_1, pressure_2, pressure_3,
                            pressure_4, pressure_5,
                            flow_1, flow_2, flow_3, flow_4, flow_5,
                            valve_1, valve_2, valve_3, valve_4, valve_5,
                            pump_1, pump_2    
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s, %s, %s, %s,
                            %s, %s
                        );
                    """, (
                        snapshot["timestamp"],
                        *snapshot["temperatures"],
                        *snapshot["pressures"],
                        *snapshot["flows"],
                        *snapshot["valves"],
                        *snapshot["pumps"]
                    ))
                    conn.commit()
                    logger.info("Datos guardados correctamente en PostgreSQL")
                except Exception as e:
                    logger.error(f"Error al guardar datos en PostgreSQL: {e}")
                finally:
                    conn.close()

        except Exception as e:
            logger.warning(f"Error polling PLC: {e}")
            with state_lock:
                current_data["status"] = f"error: {e}"
                current_data["error_count"] += 1
            client.close()

        time.sleep(POLL_INTERVAL)

def legitimate_writes():
    """Simula a un operador ajustando el setpoint desde el HMI de vez en
    cuando. Genera tráfico de escritura Modbus legítimo."""
    client = ModbusTcpClient(PLC_HOST, port=PLC_PORT, timeout=3)
    while True:
        time.sleep(random.uniform(45, 90))
        try:
            if not client.is_socket_open():
                client.connect()
            new_setpoint = random.randint(300, 400)
            client.write_register(15, new_setpoint, slave=1)
            logger.info(f"[Operador] Setpoint ajustado a {new_setpoint} vía HMI")
        except Exception as e:
            logger.warning(f"Error al ajustar setpoint: {e}")


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
    # Inicializar la base de datos
    init_db()
    # Arrancar hilo de polling
    t = threading.Thread(target=poll_plc, daemon=True, name="PLCPoller")
    threading.Thread(target=legitimate_writes, daemon=True, name="OperatorWrites").start()  
    t.start()

    logger.info("Servidor SCADA iniciado en 0.0.0.0:8080")
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
