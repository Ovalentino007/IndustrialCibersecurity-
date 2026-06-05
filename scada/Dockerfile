FROM python:3.13-slim

LABEL description="Server SCADA/HMI"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*
RUN pip3 install --no-cache-dir flask==3.0.3 pymodbus==3.6.9

COPY app.py .
COPY templates/ templates/
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

EXPOSE 8080

ENTRYPOINT ["./entrypoint.sh"]
