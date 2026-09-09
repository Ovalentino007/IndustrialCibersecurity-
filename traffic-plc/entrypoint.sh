#!/bin/sh

# Ruta hacia la red interna a través del monitor(SCADA, workstation, atacante)
echo "Configurando ruta estática hacia el resto de la red interna..."
ip route add 192.168.0.0/16 via 192.168.200.2

# Ejecutamos el comando principal del contenedor
exec python3 modbus_server.py
