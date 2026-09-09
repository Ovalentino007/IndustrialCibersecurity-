# historian/Dockerfile
FROM postgres:16-alpine

RUN apk add --no-cache iproute2

COPY entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
