#!/usr/bin/env python3
"""
Construccion del dataset de ML a partir de los logs REALES de Zeek de los
5 ataques ya validados end-to-end en este laboratorio.
 
------------------------------------------------------------------------
METODOLOGIA (para documentar en la memoria, capitulo de ML)
------------------------------------------------------------------------
 
1. UNIDAD DE ANALISIS: una fila = una conexion de `conn.log` (el nivel de
   granularidad estandar en la literatura de ML para IDS de red -- p.ej.
   los datasets de referencia CICIDS2017/NSL-KDD trabajan tambien a nivel
   de flujo/conexion, no de paquete individual).
 
2. DEDUPLICACION ENTRE INTERFACES: por el diseno de este laboratorio (un
   proceso Zeek independiente por interfaz, ver monitor-start.sh), la
   MISMA conexion logica queda registrada en los logs de DOS interfaces
   distintas (la del origen y la del destino), cada una con su propio
   uid. Se deduplica por la tupla (ip origen, puerto origen,
   ip destino, puerto destino).
 
3. ETIQUETADO: no existe un campo "label" en los logs de Zeek -- hay que
   construirlo. Se usa `notice.log` como ANCLA: cada notice ya generado
   por las reglas custom (PortscanCritical, SSHBruteForce,
   ModbusUnauthorizedWrite, DoSAttack, ModbusRequestFlood, ArpSpoofing)
   marca un timestamp real en el que ESE tipo de ataque estaba en curso.
   A cada notice se le aplica una ventana temporal [ts-PRE, ts+POST]
   (distinta por tipo de ataque, ver ATTACK_WINDOWS abajo, calibrada
   segun la duracion real de cada ataque ya documentada en las notas del
   proyecto) y toda conexion cuyo inicio caiga dentro de esa ventana
   recibe la etiqueta correspondiente. Cualquier conexion fuera de TODAS
   las ventanas se etiqueta como "benign".
 
4. CARACTERISTICAS (features):
   - Directas de conn.log: duracion, bytes/paquetes en cada sentido,
     puerto destino, protocolo, servicio, estado de conexion (conn_state),
     flags de history.
   - Derivadas simples: bytes por paquete en cada sentido.
   - Contextuales por ventana deslizante (replican exactamente la misma
     señal que ya usan las reglas de Zeek para detectar escaneos/floods,
     ver local.zeek): numero de conexiones nuevas del mismo origen en los
     ultimos 10s, numero de puertos distintos tocados por el mismo origen
     en los ultimos 60s, numero de hosts distintos tocados por el mismo
     origen en los ultimos 60s. Estas son las que de verdad permiten
     distinguir, por ejemplo, una conexion de un escaneo de puertos de una
     conexion benigna que por lo demas tiene el mismo aspecto a nivel de
     paquete individual.
   - "Payload"/atributos caracteristicos de la propia alerta (sugerencia
     del tutor del TFG, ver METODOLOGIA_ML.md): a partir de local.zeek v9
     se registra un log propio, modbus_writes.log, con el detalle de CADA
     escritura Modbus (legitima o maliciosa) -- registro/direccion, valor
     escrito, tipo de escritura. Se unen a cada conexion por `uid` y se
     resumen en `modbus_write_count` / `modbus_last_write_type` /
     `modbus_last_write_address` / `modbus_last_write_value` /
     `modbus_last_write_count`. Esto va mas alla de las estadisticas de
     flujo tipicas de conn.log (que no distinguen QUE se escribio) y
     aporta la senal mas directa posible para separar una escritura
     Modbus normal de una no autorizada (ataque 3). Si el log no existe
     todavia (monitor sin actualizar a v9), estas columnas se rellenan
     con valores neutros en vez de fallar.
 
5. Salida: un CSV con una fila por conexion, listo para scikit-learn
   (ver train_model.py).
"""
 
import argparse
import csv
import json
import re
import time
from collections import defaultdict, deque, Counter
from pathlib import Path
 
# Ventanas [pre_segundos, post_segundos] alrededor de cada notice, por
# tipo de ataque -- calibradas contra la duracion real de cada ataque.
NOTICE_TO_LABEL = {
    "OT_Detecciones::PingSweep": "portscan",
    "OT_Detecciones::PortscanCritical": "portscan",
    "OT_Detecciones::SSHBruteForce": "ssh_bruteforce",
    "OT_Detecciones::ModbusUnauthorizedWrite": "modbus_unauthorized_write",
    "OT_Detecciones::DoSAttack": "dos_network",
    "OT_Detecciones::ModbusRequestFlood": "dos_application",
    "OT_Detecciones::ArpSpoofing": "arp_spoofing",
}

ATTACK_WINDOWS = {
    "portscan": (60, 180),
    "ssh_bruteforce": (30, 130),
    "modbus_unauthorized_write": (30, 100),
    "dos_network": (10, 60),
    "dos_application": (10, 500),
    "arp_spoofing": (10, 60),
}

LABEL_PRIORITY = [
    "modbus_unauthorized_write",
    "dos_network",
    "dos_application",
    "ssh_bruteforce",
    "arp_spoofing",
    "portscan",
]
# Ventanas deslizantes para las features contextuales (replican los
# umbrales de local.zeek)
MAX_BRIDGE_GAP_S = 400
SHORT_WINDOW_S = 10
LONG_WINDOW_S = 60
 
 
def iter_log_records(root, basename_prefix):
    """Itera todos los registros JSON de todos los ficheros que empiecen
    por `basename_prefix` (p.ej. "conn" o "notice"), en CUALQUIER
    subcarpeta de interfaz y CUALQUIER rotacion, bajo `root`."""
    root = Path(root)
    pattern = re.compile(rf"^{re.escape(basename_prefix)}(\.|$)")
    for path in root.rglob("*.log"):
        if not pattern.match(path.name):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
 
 
def load_notices(root):
    notices = []
    for rec in iter_log_records(root, "notice"):
        note = rec.get("note")
        if note in NOTICE_TO_LABEL:
            notices.append((rec.get("ts"), NOTICE_TO_LABEL[note]))
    return notices
 
 
def build_label_windows(notices):
    """Devuelve una lista de (start, end, label) a partir de los notices."""
    by_label = defaultdict(list)
    for ts, label in notices:
        by_label[label].append(ts)
 
    windows = []
    for label, ts_list in by_label.items():
        ts_list.sort()
        pre, post = ATTACK_WINDOWS.get(label, (30, 60))
        cluster_start = ts_list[0]
        cluster_end = ts_list[0]
        for ts in ts_list[1:]:
            if ts - cluster_end <= MAX_BRIDGE_GAP_S:
                cluster_end = ts  # sigue la misma racha, se extiende
            else:
                windows.append((cluster_start - pre, cluster_end + post, label))
                cluster_start = ts
                cluster_end = ts
        windows.append((cluster_start - pre, cluster_end + post, label))
    return windows
 
 
def label_for_ts(ts, windows):
    # Si una conexion cae en varias ventanas solapadas, se queda con la
    # PRIMERA que encaje (orden de NOTICE_TO_LABEL / orden de aparicion en
    # notice.log) -- en la practica los ataques de este laboratorio no se
    # solapan entre si en el tiempo, asi que esto rara vez importa.
    matches = {label for start, end, label in windows if start <= ts <= end}
    if not matches:
        return "benign"
    for label in LABEL_PRIORITY:
        if label in matches:
            return label
    return next(iter(matches))
 
 
def load_connections(root):
    """Carga y deduplica conexiones de conn.log entre interfaces."""
    seen = {}
    for rec in iter_log_records(root, "conn"):
        try:
            key = (
                rec["id.orig_h"],
                rec.get("id.orig_p"),
                rec["id.resp_h"],
                rec.get("id.resp_p"),
                int(rec["ts"]),
            )
        except (KeyError, TypeError, ValueError):
            continue
        if key not in seen:
            seen[key] = rec
    return sorted(seen.values(), key=lambda r: r["ts"])
 
 
def history_flag_counts(history):
    history = history or ""
    return {
        "hist_len": len(history),
        "hist_syn": history.count("S") + history.count("s"),
        "hist_fin": history.count("F") + history.count("f"),
        "hist_rst": history.count("R") + history.count("r"),
        "hist_ack": history.count("A") + history.count("a"),
    }
 
 
def load_modbus_writes(root):
    """Carga (si existe) el log propio modbus_writes.log (anadido en
    local.zeek v9) con el "payload" de cada escritura Modbus -- direccion,
    valor, tipo de escritura -- indexado por uid."""
    by_uid = defaultdict(list)
    for rec in iter_log_records(root, "modbus_writes"):
        uid = rec.get("uid")
        if uid:
            by_uid[uid].append(rec)
    return by_uid
 
 
def build_rows(connections, windows, modbus_writes_by_uid=None, progress_every=100000):
    modbus_writes_by_uid = modbus_writes_by_uid or {}
    rows = []
    total = len(connections)
    t_start = time.time()
    # Ventanas deslizantes por IP origen para las features contextuales
    recent_conns = defaultdict(deque)   # src -> deque[ts]
    recent_ports = defaultdict(deque)   # src -> deque[(ts, dst_port)]
    recent_hosts = defaultdict(deque)   # src -> deque[(ts, dst_host)]
    port_counts = defaultdict(Counter)
    host_counts = defaultdict(Counter)

    for i, rec in enumerate(connections):
        if progress_every and i and i % progress_every == 0:
            elapsed = time.time() - t_start
            pct = 100 * i / total
            print(f"    ...{i}/{total} filas ({pct:.1f}%) en {elapsed:.1f}s")

        ts = rec["ts"]
        src = rec["id.orig_h"]
        dst = rec["id.resp_h"]
        dport = rec.get("id.resp_p")
 
        dq = recent_conns[src]
        dq.append(ts)
        while dq and ts - dq[0] > SHORT_WINDOW_S:
            dq.popleft()
        conns_same_src_10s = len(dq)
 
        dqp = recent_ports[src]
        dqp.append((ts,dport))
        pc = port_counts[src]
        pc[dport] += 1
        while dqp and ts - dqp[0][0] > LONG_WINDOW_S:
            _, old_port = dqp.popleft()
            pc[old_port] -= 1
            if pc[old_port] <= 0:
                del pc[old_port]
        distinct_ports_60s = len(pc)
 
        dqh = recent_hosts[src]
        dqh.append((ts, dst))
        hc = host_counts[src]
        hc[dst] += 1
        while dqh and ts - dqh[0][0] > LONG_WINDOW_S:
            _, old_host = dqh.popleft()
            hc[old_host] -= 1
            if hc[old_host] <= 0:
                del hc[old_host]
        distinct_hosts_60s = len(hc)
 
        orig_bytes = rec.get("orig_bytes") or 0
        resp_bytes = rec.get("resp_bytes") or 0
        orig_pkts = rec.get("orig_pkts") or 0
        resp_pkts = rec.get("resp_pkts") or 0
 
        # Features de "payload"/atributos caracteristicos de la alerta
        # (sugerencia del tutor): si esta conexion tiene escrituras Modbus
        # asociadas (log modbus_writes.log, local.zeek v9), se resumen
        # aqui -- numero de escrituras y detalle de la ULTIMA (tipo,
        # direccion/registro, valor escrito). Para conexiones sin
        # escrituras Modbus (la inmensa mayoria: SSH, portscan, ARP...) se
        # rellena con valores neutros -- no son NaN para que el modelo
        # pueda usarlos directamente sin imputacion adicional.
        writes = modbus_writes_by_uid.get(rec.get("uid"), [])
        writes_sorted = sorted(writes, key=lambda w: w.get("ts", 0))
        last_write = writes_sorted[-1] if writes_sorted else None
 
        row = {
            "ts": ts,
            "src": src,
            "dst": dst,
            "src_port": rec.get("id.orig_p"),
            "dst_port": dport,
            "proto": rec.get("proto"),
            "service": rec.get("service") or "",
            "conn_state": rec.get("conn_state") or "",
            "duration": rec.get("duration") or 0.0,
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "orig_pkts": orig_pkts,
            "resp_pkts": resp_pkts,
            "orig_ip_bytes": rec.get("orig_ip_bytes") or 0,
            "resp_ip_bytes": rec.get("resp_ip_bytes") or 0,
            "bytes_per_pkt_orig": (orig_bytes / orig_pkts) if orig_pkts else 0.0,
            "bytes_per_pkt_resp": (resp_bytes / resp_pkts) if resp_pkts else 0.0,
            "conns_same_src_10s": conns_same_src_10s,
            "distinct_dst_ports_src_60s": distinct_ports_60s,
            "distinct_dst_hosts_src_60s": distinct_hosts_60s,
            "modbus_write_count": len(writes_sorted),
            "modbus_last_write_type": (last_write["write_type"] if last_write else "none"),
            "modbus_last_write_address": (last_write.get("address", -1) if last_write else -1),
            "modbus_last_write_value": (last_write.get("value", "") if last_write else ""),
            "modbus_last_write_count": (last_write.get("count_written", 0) if last_write else 0),
            "label": label_for_ts(ts, windows),
        }
        row.update(history_flag_counts(rec.get("history")))
        rows.append(row)
 
    return rows
 
 
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zeek-logs", required=True, help="Ruta a docker/zeek/zeek_logs")
    parser.add_argument("--out", default="dataset.csv", help="Fichero CSV de salida")
    args = parser.parse_args()
 
    print(f"[+] Leyendo notices de {args.zeek_logs} ...")
    notices = load_notices(args.zeek_logs)
    print(f"    {len(notices)} notices relevantes encontrados")
    for ts, label in notices:
        print(f"      ts={ts:.1f}  label={label}")
 
    windows = build_label_windows(notices)
 
    print(f"[+] Leyendo y deduplicando conexiones de conn.log ...")
    connections = load_connections(args.zeek_logs)
    print(f"    {len(connections)} conexiones unicas tras deduplicar")
 
    print(f"[+] Leyendo modbus_writes.log (payload de escrituras Modbus, si existe) ...")
    modbus_writes_by_uid = load_modbus_writes(args.zeek_logs)
    n_writes = sum(len(v) for v in modbus_writes_by_uid.values())
    if n_writes:
        print(f"    {n_writes} escrituras Modbus encontradas en {len(modbus_writes_by_uid)} conexiones")
    else:
        print("    (no encontrado o vacio -- probablemente el monitor aun no usa local.zeek v9; "
              "se continua sin columnas de payload Modbus, rellenas con valores neutros)")
 
    print(f"[+] Construyendo features y etiquetas ...")
    rows = build_rows(connections, windows, modbus_writes_by_uid)
 
    label_counts = defaultdict(int)
    for r in rows:
        label_counts[r["label"]] += 1
    print("[+] Distribucion de clases:")
    for label, count in sorted(label_counts.items(), key=lambda x: -x[1]):
        print(f"      {label:30s} {count}")
 
    if not rows:
        print("[!] No se genero ninguna fila -- revisa la ruta de --zeek-logs")
        return
 
    fieldnames = list(rows[0].keys())
    with open(args.out, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
 
    print(f"[+] Dataset escrito en {args.out} ({len(rows)} filas, {len(fieldnames)} columnas)")
 
 
if __name__ == "__main__":
    main()