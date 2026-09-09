#!/bin/sh
ip route add 192.168.0.0/16 via 192.168.202.2
exec docker-entrypoint.sh postgres
