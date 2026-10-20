FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3 AS workload

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl libgcc-s1 libstdc++6 libssl3t64 libz3-4 zlib1g \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /sandbox \
    && chown 1000:1000 /sandbox

WORKDIR /sandbox
USER 1000:1000
CMD ["/bin/bash"]

FROM workload AS sandbox
USER root
COPY --chmod=0555 bin/openshell-sandbox /openshell-sandbox
USER 65532:65532
ENTRYPOINT ["/openshell-sandbox"]

FROM workload AS supervisor
USER root
COPY --chmod=0555 bin/openshell-supervisor /openshell-supervisor
ENTRYPOINT ["/openshell-supervisor"]
