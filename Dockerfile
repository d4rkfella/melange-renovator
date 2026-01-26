FROM debian:trixie-slim@sha256:77ba0164de17b88dd0bf6cdc8f65569e6e5fa6cd256562998b62553134a00ef0

ARG TARGETARCH

ENV DEBIAN_FRONTEND="noninteractive"

USER root

RUN \
    apt-get update \
    && \
    apt-get install -y --no-install-recommends --no-install-suggests \
    bash \
    ca-certificates \
    tzdata \
    chromium \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && apt-get autoremove -y \
    && apt-get clean

COPY --chmod=555 melange-renovator-${TARGETARCH} /usr/local/bin/melange-renovator

USER 1001

ENTRYPOINT ["/usr/local/bin/melange-renovator"]
