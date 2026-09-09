#!/bin/bash



PCAP_DIR="/capture"
ZEEK_DIR="/zeek_logs"
CONFIG="/zeek_config/local.zeek"

echo "============================================="
echo "  Monitor de red IDS — TFG Industrial"
echo "  Topologia de estrella: 1 interfaz por host"
echo "  PCAPs   : $PCAP_DIR"
echo "  Logs    : $ZEEK_DIR"
echo "============================================="

cleanup() {
    echo "[!] Apagando monitor..."
    kill $ALL_PIDS 2>/dev/null
    exit 0
}
trap cleanup SIGTERM SIGINT

ALL_PIDS=""

ip route del default 2>/dev/null || true
echo "[+] Ruta por defecto eliminada. Rutas actuales: "
ip route show

IFACES=$(ip -o link show | awk -F': ' '{print $2}' | cut -d'@' -f1 | grep '^eth')
echo "[+] Interfaces detectadas: $IFACES"

# ── tcpdumpn todadas l s interfaces ───────────────────────────────
for IFACE in $IFACES; do
    echo "[+] Iniciando tcpdump en $IFACE..."
    tcpdump \
        -i "$IFACE" \
        -w "$PCAP_DIR/capture_${IFACE}_%Y%m%d_%H%M%S.pcap" \
        -G 300 \
        -W 10000 \
        -s 0 \
        -n &
    ALL_PIDS="$ALL_PIDS $!"
done

sleep 2

# ── Ze eskscuchando en todas las interfaces a la vIR ─────────────────────
for IFACE in $IFACES; do
    IFACE_LOG_DIR="$ZEEK_DIR/$IFACE"
    mkdir -p "$IFACE_LOG_DIR"
    echo "[+] Iniciando Zeek en $IFACE (logs en $IFACE_LOG_DIR)"
    (cd "$IFACE_LOG_DIR" && exec zeek -i "$IFACE" "$CONFIG") &
    ALL_PIDS="$ALL_PIDS $!"
    echo "   Zeek PID ($IFACE): $!"
done

echo "[+] Monitor activo."
echo "    Logs Zeek : $ZEEK_DIR"
echo "    PCAPs     : $PCAP_DIR"

wait
echo "[!] Todos los procesos han terminado."
