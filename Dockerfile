# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage container image for the `openshell-risk-guard` sidecar.
# Build from the repository root (the directory that holds both `openshell-risk-guard/` and `OpenShell/`):
#   docker build -f openshell-risk-guard/Dockerfile -t openshell-risk-guard:local .

# OpenShell's prebuilt Z3 needs glibc 2.38+ and libstdc++ 13+, so build and run on Debian 13 (trixie).
FROM rust:1.95-trixie AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    g++ \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY OpenShell ./OpenShell
COPY openshell-risk-guard ./openshell-risk-guard

RUN cargo build \
    --manifest-path openshell-risk-guard/Cargo.toml \
    --locked \
    --release \
    --bin openshell-risk-guard

FROM debian:trixie-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 riskguard \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin riskguard \
    && mkdir -p /var/lib/openshell-risk-guard \
    && chown -R 65532:65532 /var/lib/openshell-risk-guard

COPY --from=builder /workspace/openshell-risk-guard/target/release/openshell-risk-guard /usr/local/bin/openshell-risk-guard

USER 65532:65532
WORKDIR /var/lib/openshell-risk-guard
VOLUME ["/var/lib/openshell-risk-guard"]

EXPOSE 50061

# The sidecar reads its inputs from mounted files. On this shared listener it
# refuses to start without all of them (no plaintext, no built-in keys):
#   RISK_GUARD_PUBLIC_KEY_PEM   gateway extension-JWT public key
#   RISK_GUARD_TLS_CERT / _KEY  server certificate chain and private key
#   RISK_GUARD_HMAC_KEY_FILE    resource HMAC key, at least 32 bytes
#   RISK_GUARD_DEFAULT_TASK_PROFILE  an already-imported baseline profile
#   RISK_GUARD_API_SEMANTICS    route map for the protected APIs (recommended)
#   RISK_GUARD_AGENT_BINDING_PRINCIPALS  optional: operator:<subject>,user:<subject> allowed
#                               to bind sandboxes to agent IDs by annotation (default: none)
#   RISK_GUARD_WORKLOAD_FROM_PRINCIPAL  optional: true derives each unlabeled sandbox's workload
#                               from its workspace and the authenticated creating principal
#   RISK_GUARD_ALLOW_LOCAL_DEV_PRINCIPAL  local testing only: let OpenShell's unauthenticated
#                               local-development user own a workload (default: refused)
# Health: grpc.health.v1.Health/Check on the same port.
ENTRYPOINT ["/usr/local/bin/openshell-risk-guard"]
CMD ["serve", "--listen", "0.0.0.0:50061", "--db", "/var/lib/openshell-risk-guard/risk-guard.db"]
