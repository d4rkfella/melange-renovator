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
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && apt-get autoremove -y \
    && apt-get clean

RUN groupadd -r -g 65532 nonroot \
    && useradd  -r -u 65532 -g nonroot -M -s /usr/sbin/nologin nonroot

COPY --chmod=555 melange-renovator-${TARGETARCH} /usr/local/bin/melange-renovator

USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/melange-renovator"]
