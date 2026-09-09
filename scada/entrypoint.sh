#!/bin/sh

# Indicamos al SCADA que para llegar al resto de la red debe enlazarse punto a punto
echo "Configurando ruta estática hacia el resto de red interna..."
ip route add 192.168.0.0/16 via 192.168.201.2

#Arrancamos SSH en segundo plano
echo "Iniciando servicio SSH..."
/usr/sbin/sshd -e

# Lanzamos la aplicación de Flask sustituyendo el proceso (PID 1)
exec python3 app.py

