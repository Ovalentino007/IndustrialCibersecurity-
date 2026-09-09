FROM ubuntu:24.04

LABEL description="Nodo atacante - Herramienta de Red y OT"
LABEL arch="ARM64 nativo"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    net-tools \
    nmap \
    hping3 \
    curl \
    python3 \
    python3-pip \
    openssh-client \
    hydra \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir --break-system-packages \
    scapy \
    pymodbus==3.6.9

RUN mkdir -p /scripts

COPY start.sh /start.sh
RUN chmod +x start.sh

WORKDIR /scripts

ENTRYPOINT ["/start.sh"]

