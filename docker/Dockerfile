# =============================================================
# Imagen base: zeek/zeek:lts
# Imagen oficial del equipo de Zeek — multi-arch
# Soporta: linux/amd64  Y  linux/arm64 (Apple Silicon)
# NO usar ubuntu + OBS repo → solo tiene paquetes x86_64
# =============================================================
FROM zeek/zeek:lts

LABEL description="Monitor de red: Zeek IDS + tcpdump — TFG IDS Industrial"
LABEL arch="multi-arch (amd64 + arm64)"

ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Madrid

# ── Herramientas complementarias ──────────────────────────────
# Zeek ya está instalado en la imagen base, solo añadimos:
#   tcpdump   → captura raw .pcap en paralelo a Zeek
#   tshark    → análisis puntual de ficheros .pcap (opcional)
#   net-tools → comandos ifconfig, netstat
#   iproute2  → comando ip (para activar modo promiscuo)
#   python3   → scripts de post-procesado de logs
RUN apt-get update && apt-get install -y --no-install-recommends\
    tcpdump \
    net-tools \
    iproute2 \
    iputils-ping \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# ── Librerías Python para análisis de logs ────────────────────
RUN pip3 install --no-cache-dir --break-system-packages\
    pymodbus==3.6.9

# ── Estructura de directorios ─────────────────────────────────
RUN mkdir -p /capture /zeek_logs /zeek_config

# ── Configuración y script de arranque ───────────────────────
# La imagen zeek/zeek instala Zeek en /usr/local/zeek
# y ya lo añade al PATH — no hace falta ENV PATH manualmente
COPY start.sh         /start.sh

RUN chmod +x start.sh

WORKDIR /capture

ENTRYPOINT  ["/start.sh"]
