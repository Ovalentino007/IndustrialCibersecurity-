# =============================================================
# local.zeek — Configuración Zeek para red OT industrial
# Compatible con zeek/zeek:lts (Zeek 6.x)
# =============================================================

# ── Red local ─────────────────────────────────────────────────
redef Site::local_nets = {
	192.168.100.0/24, # Zona de control (SCADA, Atacante)
	192.168.200.0/24  # Zona de proceso (PLC, Historian)
};

# ── Protocolos base ───────────────────────────────────────────
@load base/protocols/conn        # Conexiones TCP/UDP/ICMP → conn.log
@load base/protocols/http        # HTTP                     → http.log
@load base/protocols/dns         # DNS                      → dns.log
@load base/protocols/ftp         # FTP                      → ftp.log
@load base/protocols/ssh         # SSH                      → ssh.log
@load base/protocols/modbus      # Modbus TCP industrial   → modbus.log

# ── Frameworks ────────────────────────────────────────────────
@load base/frameworks/notice     # Alertas + weird.log incluido
@load base/frameworks/files      # Extracción de ficheros transferidos


# ── Detección de escaneos de puertos ─────────────────────────
@load policy/protocols/modbus/track-memmap
@load policy/misc/detect-traceroute
# ── Puerto Modbus no estándar ─────────────────────────────────
event zeek_init(){
  Analyzer::register_for_port(Analyzer::ANALYZER_MODBUS, 5020/tcp);
}

# ── Rotación de logs cada 10 minutos ─────────────────────────
redef Log::default_rotation_interval = 10 mins;

# ── Directorio de salida ──────────────────────────────────────
redef Log::default_logdir = "/zeek_logs";

# Zeek escribe los logs directamente en formato JSON
@load policy/tuning/json-logs

# Forzamos a Zeek a analizar todos los paquetes aunque la tarjeta de red no haya calculado el checksum
redef ignore_checksums = T;

# === REGLAS PERSONALIZADAS PARA DETECTAR RECONOCIMIENTO ===

module OT_Detecciones;

export {
    redef enum Notice::Type += {
        PingSweep,
        PortscanCritical  # <--- Creamos una alerta propia para tu regla de puertos
    };
}

# Detectar ping sweep (descubrimiento de hosts)
event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
    NOTICE([$note=OT_Detecciones::PingSweep,
            $msg=fmt("Ping sweep detectado desde %s a %s", c$id$orig_h, c$id$resp_h),
            $conn=c]);
}

# Detectar escaneo de puertos en puertos críticos
event connection_attempt(c: connection) {
    if (c$id$resp_p == 5020/tcp ||  # Modbus TCP (PLC)
        c$id$resp_p == 8080/tcp ||  # Dashboard SCADA
        c$id$resp_p == 5432/tcp ||  # PostgreSQL (Historian)
        c$id$resp_p == 502/tcp) {   # Modbus TCP estándar
        
        # CORREGIDO: Usamos la nueva alerta del módulo actual
        NOTICE([$note=OT_Detecciones::PortscanCritical,
                $msg=fmt("Escaneo de puertos detectado a %s:%d desde %s",
                         c$id$resp_h, c$id$resp_p, c$id$orig_h),
                $conn=c]);
    }
}