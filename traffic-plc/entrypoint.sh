#!/bin/sh

# Indicamos al PLC como responder a la red de control a través del monitor (.200.200)
echo "Configurando ruta estática hacia la red de control..."
ip route add 192.168.100.0/24 via 192.168.200.200

# Ejecutamos el comando principal del contenedor
exec python3 modbus_server.py
