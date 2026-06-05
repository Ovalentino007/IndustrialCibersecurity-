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
@load base/protocols/http        # HTTP                    → http.log
@load base/protocols/dns         # DNS                     → dns.log
@load base/protocols/ftp         # FTP                     → ftp.log
@load base/protocols/ssh         # SSH                     → ssh.log
@load base/protocols/modbus      # Modbus TCP industrial   → modbus.log

# ── Frameworks ────────────────────────────────────────────────
@load base/frameworks/notice     # Alertas + weird.log incluido
@load base/frameworks/files      # Extracción de ficheros transferidos

# ── Detección de escaneos de puertos ─────────────────────────
# @load policy/misc/scan
@load policy/protocols/modbus/track-memmap

# ── Puerto Modbus no estándar ─────────────────────────────────
# Nuestro PLC usa 5020 en vez del estándar 502 (permisos macOS).
# FIX: sintaxis correcta en Zeek 5+/6+ es += no const &redef
#redef Modbus::ports += { 5020/tcp };
event zeek_init(){
  Analyzer::register_for_port(Analyzer::ANALYZER_MODBUS,5020/tcp);
}

# ── Rotación de logs cada 10 minutos ─────────────────────────
# Granularidad fina para etiquetar benigno vs malicioso
redef Log::default_rotation_interval = 10 mins;

# ── Directorio de salida ──────────────────────────────────────
redef Log::default_logdir = "/zeek_logs";

# Zeek escribe los logs directamente en formato JSON
@load policy/tuning/json-logs

# Forzamos a Zeek a analizar todos los paquetes aunque la tarjeta de red no haya calculado el checksum
redef ignore_checksums = T;

