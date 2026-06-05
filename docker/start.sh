#!/bin/bash
# =============================================================
# start.sh — Arranca el monitor de red completo
# Lanza en paralelo:
#   1. tcpdump  → captura raw en ficheros .pcap rotados
#   2. Zeek     → análisis en tiempo real + logs estructurados
# =============================================================

IFACES=$(ip -o link show | awk -F ': ' '{print $2}' | grep -E '^eth|^br' | cut -d '@' -f1)
FIRST_IFACE=$(echo $IFACES | awk '{print $1}')

if [ -z "$FIRST_IFACE" ]; then
     echo "[!]NO se detectaron interfaces eth válidas. Usamos eth0 por defecto."
     FIRST_IFACE="eth0"
fi

echo "[+]Interfaces detectadas: $IFACES"
echo "[+]Escuchando de forma principal en interfaz: $FIRST_IFACE"

PCAP_DIR="/capture"
ZEEK_DIR="/zeek_logs"
CONFIG="/zeek_config/local.zeek"

echo "============================================="
echo "  Monitor de red IDS — TFG Industrial"
echo "  Interfaz : $IFACE"
echo "  PCAPs    : $PCAP_DIR"
echo "  Zeek logs: $ZEEK_DIR"
echo "============================================="


# ── tcpdump ──────────────────────────────────────────────────
# -i eth0       → interfaz de la red OT
# -w fichero    → captura binaria .pcap con nombre timestamp
# -G 300        → rota el fichero cada 300s (5 minutos)
# -W 10000      → máximo 10000 ficheros (evita llenar disco)
# -s 0          → captura el paquete completo (sin truncar)
# -n            → no resolver nombres DNS (más rápido)
# FIX: eliminado -C 50 — en ARM tcpdump, usar -C y -G juntos
# genera nombres incorrectos sin el patrón strftime
echo "[+] Iniciando tcpdump (rotación cada 5 min)..."
tcpdump \
    -i "$FIRST_IFACE" \
    -w "$PCAP_DIR/capture_%Y%m%d_%H%M%S.pcap" \
    -G 300 \
    -W 10000 \
    -s 0 \
    -n \
    &
TCPDUMP_PID=$!
echo "    tcpdump PID: $TCPDUMP_PID"

# Dar tiempo a tcpdump para abrir la interfaz antes de Zeek
sleep 2

# ── Zeek ─────────────────────────────────────────────────────
# En la imagen zeek/zeek:lts, el binario está en PATH
# Los logs se escriben en el directorio actual → cd $ZEEK_DIR primero
echo "[+] Iniciando Zeek en modo live..."
cd "$ZEEK_DIR"
zeek \
    -i "$FIRST_IFACE" \
    "$CONFIG" \
    &
ZEEK_PID=$!
echo "    Zeek PID: $ZEEK_PID"

echo "[+] Monitor activo. Capturando tráfico de la red OT..."
echo "    Para ver logs en tiempo real:"
echo "    tail -f $ZEEK_DIR/conn.log"

# Apagado limpio: matar tcpdump y Zeek al recibir señal
trap "echo '[!] Apagando monitor...'; kill $TCPDUMP_PID $ZEEK_PID 2>/dev/null; exit 0" SIGTERM SIGINT

# Bucle de vigilancia: si alguno muere, lo registra y espera al otro
while kill -0 $TCPDUMP_PID 2>/dev/null && kill -0 $ZEEK_PID 2>/dev/null; do
    sleep 5
done

echo "[!] Uno de los procesos terminó inesperadamente"
kill $TCPDUMP_PID $ZEEK_PID 2>/dev/null
