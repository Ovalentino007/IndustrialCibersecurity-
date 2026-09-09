FROM python:3.13-slim

LABEL description="Server SCADA/HMI"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends iproute2 openssh-server \
&& rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash scada && echo "scada:scada123" | chpasswd \
&& mkdir -p /var/run/sshd /home/scada/.ssh \
&& chmod 700 /home/scada/.ssh

RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
&& sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config \
&& ssh-keygen -A

RUN pip3 install --no-cache-dir flask==3.0.3 pymodbus==3.6.9 psycopg2-binary

COPY app.py .
COPY templates/ templates/
COPY entrypoint.sh .

RUN chmod +x entrypoint.sh

EXPOSE 8080 22

ENTRYPOINT ["./entrypoint.sh"]
