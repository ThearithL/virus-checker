FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 clamav clamav-freshclam ca-certificates tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY bot.py start.sh /app/
RUN chmod 755 /app/start.sh && chown -R clamav:clamav /var/lib/clamav /var/log/clamav
USER clamav
ENTRYPOINT ["/usr/bin/tini", "-g", "--", "/app/start.sh"]
