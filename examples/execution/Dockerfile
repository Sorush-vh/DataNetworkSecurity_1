FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 gcc g++ libc6-dev binutils make \
    && rm -rf /var/lib/apt/lists/*
