FROM golang:1.25-bookworm

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      iproute2 \
      iputils-ping \
      netcat-openbsd \
      curl \
      tcpdump \
      net-tools \
      procps \
      vim-tiny \
      less \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Long-lived lab: stay up until `docker compose stop`.
CMD ["sleep", "infinity"]
