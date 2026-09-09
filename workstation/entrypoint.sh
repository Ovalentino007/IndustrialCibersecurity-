#!/bin/sh
ip route add 192.168.0.0/16 via 192.168.203.2
exec python3 /app/workstation_start.py
