
# =============================================================
# local.zeek — Configuración Zeek para red OT industrial
# Compatible con zeek/zeek:lts (Zeek 6.x)
# =============================================================

# ── Red local ─────────────────────────────────────────────────
redef Site::local_nets = {
	192.168.200.0/29,  # Zona de proceso (PLC)
	192.168.201.0/29,  # Zona de control (SCADA)
	192.168.202.0/29,  # Zona de control (Historian)
	192.168.203.0/29,  # Zona de control (Workstation)
	192.168.204.0/29  # Zona de control (Atacante)
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
@load policy/misc/detect-traceroute

# ── Puerto Modbus no estándar ─────────────────────────────────
event zeek_init(){
  Analyzer::register_for_port(Analyzer::ANALYZER_MODBUS, 5020/tcp);
}

# ── Rotación de logs cada 10 minutos ─────────────────────────
redef Log::default_rotation_interval = 10 mins;

# ── Directorio de salida ──────────────────────────────────────

# Zeek escribe los logs directamente en formato JSON
@load policy/tuning/json-logs

# Forzamos a Zeek a analizar todos los paquetes aunque la tarjeta de red no haya calculado el checksum
redef ignore_checksums = T;

# === REGLAS PERSONALIZADAS PARA DETECTAR RECONOCIMIENTO ===

module OT_Detecciones;

export {
    redef enum Notice::Type += {
        PingSweep, # <--  Creamos una alerta propia para deteccion de pings de barrido
        PortscanCritical,  # <--- Creamos una alerta propia para tu regla de puertos
        SSHBruteForce,     # <--- Creamos una alerta propia para el bruteforce de credenciales
        ModbusUnauthorizedWrite, # <-- Creamos una alerta propia para escritura Modbus no autorizada de coils/registros
        DoSAttack,         # <--- Denegacion de servicios (volumen alto de conexiones nuevas)   
        ModbusRequestFlood, # <--- Denegacion de servicios (volumen alto de peticiones por conexion)
        ArpSpoofing        # <--- Envenenamiento de cache ARP (Ip con MACs en conflicto)
};
}

export {
    redef enum Log::ID += { MODBUS_WRITES_LOG };

    type ModbusWriteInfo: record {
        
        ts: time &log;
        uid: string &log;
        src: addr &log;
        dst: addr &log;
        write_type: string &log;
        address: count &log;
        value: string &log;
        count_written: count &log;
    };
}

event zeek_init(){
   
    Log::create_stream(OT_Detecciones::MODBUS_WRITES_LOG,
                        [$columns=ModbusWriteInfo, $path="modbus_writes"]); 
}

# -- Detectar ping sweep (descubrimiento de hosts)

global ping_targets: table[addr] of set[addr] &create_expire=1mins;
const PING_SWEEP_THRESHOLD = 5;

event icmp_echo_request(c: connection, info: icmp_info, id: count, seq: count, payload: string) {
    
    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    if (src !in ping_targets)
        ping_targets[src] = set();
    add ping_targets[src][dst];

    if (|ping_targets[src]| >= PING_SWEEP_THRESHOLD){
        NOTICE([$note=OT_Detecciones::PingSweep,
                $msg=fmt("Ping sweep detectado desde %s (%d hosts distintos en menos de 1 minuto)",
                src, |ping_targets[src]|),
                $conn=c,
                $identifier=cat(src)]);
        ping_targets[src] = set();
    }
}

# Detectar escaneo de puertos en puertos críticos

global portscan_ports: table[addr, addr] of set[port] &create_expire=1mins;
const PORTSCAN_PORT_THRESHOLD = 15;

global portscan_targets: table[addr] of set[addr] &create_expire=5mins;
const PORTSCAN_HOST_THRESHOLD = 3;

function track_scan_attempt(c: connection){
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;

    if ([src,dst] !in portscan_ports)
        portscan_ports[src,dst] = set();
    add portscan_ports[src,dst][dport];

    if (|portscan_ports[src,dst]| >= PORTSCAN_PORT_THRESHOLD){
        NOTICE([$note=OT_Detecciones::PortscanCritical,
                $msg=fmt("Escaneo de puertos detectado: %s ha tocado %d puertos distintos en %s menos de 1 minuto",
                         src, |portscan_ports[src,dst]|, dst),
                $conn=c,
                $identifier=cat(src, dst, "ports")]);
        portscan_ports[src,dst] = set();
    }

    if (dport == 5020/tcp ||  # Modbus TCP (PLC)
        dport == 8080/tcp ||  # Dashboard SCADA
        dport == 5432/tcp ||  # PostgreSQL (Historian)
        dport == 502/tcp) {   # Modbus TCP estándar
        
        if (src !in portscan_targets)
            portscan_targets[src] = set();
        add portscan_targets[src][dst];

        if (|portscan_targets[src]| >= PORTSCAN_HOST_THRESHOLD){
            NOTICE([$note=OT_Detecciones::PortscanCritical,
                    $msg=fmt("Escaneo de puertos detectado: %s ha tocado %d hosts en puertos criticos (ultimo: %s:%d)",
                             src, |portscan_targets[src]|, dst, dport),
                    $conn=c,
                    $identifier=cat(src, "hosts")]);
            portscan_targets[src] = set();
        }
     }
}

event connection_attempt(c: connection){
    track_scan_attempt(c);
}

event connection_rejected(c: connection){
    track_scan_attempt(c);
}

# ── Detección de fuerza bruta SSH ─────────────────────────────
# Tabla que acumula intentos fallidos por IP origen.
# Se limpia automáticamente cada 5 minutos (create_expire).

global ssh_failed: table[addr] of count &default=0 
                                         &create_expire=5mins;

event ssh_auth_result(c:connection, result: bool, auth_attempts: count){

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    # result=F indica autenticación fallida
    if (result == F) {
        ssh_failed[src] += 1;

        if (ssh_failed[src] >= 5) {
            NOTICE([$note=OT_Detecciones::SSHBruteForce,
                    $msg=fmt("Fuerza bruta SSH detectada desde %s hacia %s (%d intentos fallidos)", src, dst, ssh_failed[src]),
                    $conn=c,
                    $identifier=cat(src)]);

            ssh_failed[src] = 0;
        }
    }
}

# ---Detección de escritura Modbus no autorizada ------------

const SCADA_IP: addr = 192.168.201.3;
const PLC_SETPOINT_ADDR = 15;
const SETPOINT_MIN = 300;
const SETPOINT_MAX = 400;

event modbus_write_single_coil_request(c: connection, headers: ModbusHeaders, address: count, value: bool){

    local src = c$id$orig_h;
    local winfo_coil: ModbusWriteInfo = [$ts=network_time(), $uid=c$uid, $src=c$id$orig_h, $dst=c$id$resp_h, $write_type="coil", $address=address, $value=fmt("%s", value), $count_written=1];
    Log::write(OT_Detecciones::MODBUS_WRITES_LOG, winfo_coil);
    NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
            $msg=fmt("Escritura Modbus no autorizada: %s ha escrito el coil %d = %s en el PLC (ningun cliente legitimo puede escribir coils por red)",
                     src, address, value),
            $conn=c,
            $identifier=cat(src, "coil", address)]);
}

event modbus_write_multiple_coils_request(c: connection, headers: ModbusHeaders, start_address: count, coils: ModbusCoils) {

    local src = c$id$orig_h;
    local winfo_coils: ModbusWriteInfo = [$ts=network_time(), $uid=c$uid, $src=c$id$orig_h, $dst=c$id$resp_h, $write_type="coils", $address=start_address, $value=fmt("%s", coils), $count_written=|coils|];
    Log::write(OT_Detecciones::MODBUS_WRITES_LOG, winfo_coils);
    NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
            $msg=fmt("Escritura Modbus no autorizada: %s ha escrito %d coils a partir del %d en el PLC",
                     src, |coils|, start_address),
            $conn=c,
            $identifier=cat(src, "coils", start_address)]);
}

event modbus_write_single_register_request(c: connection, headers: ModbusHeaders, address: count, value: count) {

    local src = c$id$orig_h;
    local winfo_register: ModbusWriteInfo = [$ts=network_time(), $uid=c$uid, $src=c$id$orig_h, $dst=c$id$resp_h, $write_type="register", $address=address, $value=fmt("%d", value), $count_written=1];    
    Log::write(OT_Detecciones::MODBUS_WRITES_LOG, winfo_register);


    if (src != SCADA_IP){
        NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
                $msg=fmt("Escritura Modbus no autorizada: origen %s (no es SCADA) ha escrito en el registro %d = %d en el PLC",
                         src, address, value),
                $conn=c,
                $identifier=cat(src, "register", address)]);
    }
    else if (address != PLC_SETPOINT_ADDR) {
        NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
                $msg=fmt("Escritura Modbus anómala: SCADA ha escrito en el registro %d (solo se esperaba el %d, el setpoint)",
                         address, PLC_SETPOINT_ADDR),
                $conn=c,
                $identifier=cat(src, "register", address)]);
    }
    else if (value < SETPOINT_MIN || value > SETPOINT_MAX) {
        NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
                $msg=fmt("Escritura Modbus anómala: setpoint fuera de rango (%d, esperado %d-%d) escrito desde %s",
                         value, SETPOINT_MIN, SETPOINT_MAX, src),
                $conn=c,
                $identifier=cat(src, "register", address)]);
    }
}

event modbus_write_multiple_registers_request(c: connection, headers: ModbusHeaders, start_address: count, registers: ModbusRegisters) {
    
    local src = c$id$orig_h;
    local winfo_registers: ModbusWriteInfo = [$ts=network_time(), $uid=c$uid, $src=c$id$orig_h, $dst=c$id$resp_h, $write_type="registers", $address=start_address, $value=fmt("%s", registers), $count_written=|registers|];
    Log::write(OT_Detecciones::MODBUS_WRITES_LOG, winfo_registers);
    NOTICE([$note=OT_Detecciones::ModbusUnauthorizedWrite,
            $msg=fmt("Escritura Modbus no autorizada, %s ha escrito %d registros a partir del %d en el PLC",
                     src, |registers|, start_address),
            $conn=c,
            $identifier=cat(src, "registers", start_address)]);
}

# -- Deteccion de denegacion de servicios por SYN flood contra el PLC --

global dos_conn_count: table[addr, addr] of count &default=0 &create_expire=10secs;
const DOS_CONN_THRESHOLD = 50;

event new_connection(c: connection){
    
    local src = c$id$orig_h;
    local dst = c$id$resp_h;
    local dport = c$id$resp_p;

    dos_conn_count[src, dst] +=1;
 
    if (dos_conn_count[src, dst] >= DOS_CONN_THRESHOLD) {
        NOTICE([$note=OT_Detecciones::DoSAttack,
                $msg=fmt("Posible denegacion de servicio: %s ha abierto %d conexiones nuevas hacia %s (ultimo puerto: %d) en menos de 10 segs",
                         src, dos_conn_count[src,dst], dst, dport),
                $conn=c,
                $identifier=cat(src, dst)]);
        dos_conn_count[src, dst] = 0;

    }
}

# -- Deteccion de denegacion de servicios a nivel de aplicacion: flood peticiones Modbus

global modbus_req_count: table[addr, addr] of count &default=0 &create_expire=10secs;
const MODBUS_FLOOD_THRESHOLD = 100;

event modbus_message(c: connection, headers: ModbusHeaders, is_orig: bool)
{

    if(!is_orig)
       return;

    local src = c$id$orig_h;
    local dst = c$id$resp_h;

    modbus_req_count[src, dst] +=1;

    if (modbus_req_count[src, dst] >= MODBUS_FLOOD_THRESHOLD) {
        NOTICE([$note=OT_Detecciones::ModbusRequestFlood,
                $msg=fmt("Posible denegacion de servicios a nivel de aplicacion: %s ha enviado %d peticiones Modbus hacia %s en menos de 10 segundos",
                          src, modbus_req_count[src, dst], dst),
                $conn=c,
                $identifier=cat(src, dst)]);
        modbus_req_count[src, dst] = 0;
    }
}

# -- Deteccion de ARP Spoofing --

global arp_known_mac: table[addr] of string;

function check_arp_binding(SPA: addr, SHA: string){
         
    if (SPA in arp_known_mac && arp_known_mac[SPA] != SHA){
        NOTICE([$note=OT_Detecciones::ArpSpoofing,
                $msg=fmt("Possible ARP Spoofing: %s ha cambiado de MAC %s a %s",
                         SPA, arp_known_mac[SPA], SHA),
                $src=SPA,
                $identifier=cat(SHA)]);
    }
    arp_known_mac[SPA] = SHA;
}

event arp_reply(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string){

    check_arp_binding(SPA, SHA);
}

event arp_request(mac_src: string, mac_dst: string, SPA: addr, SHA: string, TPA: addr, THA: string){
    check_arp_binding(SPA, SHA);
}
