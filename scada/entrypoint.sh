#!/bin/sh

# Indicamos al SCADA que para llegar al PLC debe saltar a traves del monitor(.100.200)
echo "Configurando ruta estática hacia la red de proceso..."
ip route add 192.168.200.0/24 via 192.168.100.200

# Lanzamos la aplicación de Flask sustituyendo el proceso (PID 1)
exec python3 app.py

