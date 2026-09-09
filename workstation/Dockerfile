# workstation/Dockerfile

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir pymodbus==3.6.9 requests

COPY workstation_start.py /app/workstation_start.py
COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
