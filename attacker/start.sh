#!/bin/sh

sleep 10

# Ruta hacia la red de proceso (siempre fija)
echo "[+] Configurando rutas hacia el resto del laboratorio"
ip route add 192.168.0.0/16 via 192.168.204.2 2>/dev/null || true

echo "[*] Enrutamiento configurado."
ip route show

# Mantener el contenedor vivo
tail -f /dev/null
