# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# Multi-stage container image for the `openshell-risk-guard` sidecar.
# Build from this repository's root; nothing else is needed. The OpenShell crates it uses are fetched from NVIDIA's
# public repository at the commit pinned in Cargo.toml, so the build needs network access to github.com:
#   docker build -t openshell-risk-guard:local .

# OpenShell's prebuilt Z3 needs glibc 2.38+ and libstdc++ 13+, so build and run on Debian 13 (trixie).
# Base images are pinned by digest so a rebuild uses the same bytes. To update one, pull the new tag, read its digest, change it here, and rebuild.
FROM rust:1.95-trixie@sha256:f49565f188ee00bc2a18dd418183f2c5f23ef7d6e691890517ed341a598f67c3 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    g++ \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
COPY . ./openshell-risk-guard

RUN cargo build \
    --manifest-path openshell-risk-guard/Cargo.toml \
    --locked \
    --release \
    --bin openshell-risk-guard

RUN mkdir -p /out/var/lib/openshell-risk-guard

# A distroless runtime: glibc, libstdc++ and CA certificates, with no shell, package manager, util-linux or login. The service needs
# none of those (its probes run the binary itself), and every one of them is something to patch.
FROM gcr.io/distroless/cc-debian13@sha256:83b9b50586253821cf63ffcec87d3d94265a093ad30da232039af962dd8f4edf AS runtime

COPY --from=builder --chown=65532:65532 /out/var/lib/openshell-risk-guard /var/lib/openshell-risk-guard
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
