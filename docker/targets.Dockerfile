FROM --platform=linux/amd64 debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONPATH=/project/src \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-pytest \
        gcc g++ make binutils git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /project
