# Binary is pre-cross-compiled by `task build` into bin/linux-<arch>/.
# ALPINE_BASE_IMAGE_VERSION and LPROBE_VERSION are pinned in versions.env and
# passed by `task image`; there are deliberately no defaults so builds fail
# loudly without them.
ARG ALPINE_BASE_IMAGE_VERSION
ARG LPROBE_VERSION

FROM ghcr.io/fivexl/lprobe:${LPROBE_VERSION} AS lprobe

FROM alpine:${ALPINE_BASE_IMAGE_VERSION}

# An ARG declared before a FROM is outside of a build stage, so it must be
# redeclared inside the stage to be usable after FROM.
ARG TARGETARCH

LABEL org.opencontainers.image.title="harbor-scanner-clair" \
      org.opencontainers.image.description="Harbor scanner adapter for Clair" \
      org.opencontainers.image.source="https://github.com/container-registry/harbor-scanner-clair" \
      org.opencontainers.image.licenses="Apache-2.0"

# Ids are explicit because the Helm chart's podSecurityContext pins
# runAsUser/runAsGroup/fsGroup to 10000; the two must stay in sync.
RUN addgroup -S -g 10000 scanner && adduser -S -G scanner -u 10000 -h /home/scanner scanner

COPY --from=lprobe /lprobe /lprobe
COPY bin/linux-${TARGETARCH}/scanner-clair /home/scanner/bin/scanner-clair

RUN chown -R scanner:scanner /home/scanner

# The API server binds SCANNER_API_SERVER_ADDR, default :8080; the kube manifest
# and the Harbor integration use :8443 with TLS.
EXPOSE 8080
EXPOSE 8443
# Shell form so port and scheme follow SCANNER_API_SERVER_ADDR and the TLS config
# at runtime (exec form gets no env expansion).
HEALTHCHECK --interval=10s --timeout=5s --retries=5 \
    CMD addr="${SCANNER_API_SERVER_ADDR:-:8080}"; \
        /lprobe -port "${addr##*:}" -endpoint /probe/ready ${SCANNER_API_SERVER_TLS_CERTIFICATE:+-tls -tls-no-verify}

USER scanner

# No ENV version stamp: GetScannerMetadata() hardcodes Clair/CoreOS/2.x in
# pkg/etc/config.go and reads no env var, unlike harbor-scanner-trivy.
ENTRYPOINT ["/home/scanner/bin/scanner-clair"]
