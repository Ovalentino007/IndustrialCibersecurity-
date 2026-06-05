FROM python:3.13-slim

LABEL description="Simulation PLC Modbus TCP"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir pymodbus==3.6.9

COPY modbus_server.py .
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

EXPOSE 5020

ENTRYPOINT ["./entrypoint.sh"]
