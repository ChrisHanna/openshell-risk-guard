# SPDX-FileCopyrightText: Copyright (c) 2026 Christopher Hanna.
# SPDX-License-Identifier: Apache-2.0
#
# The in-cluster agent fleet: the `openshell` CLI, the fleet scripts and each agent's policy and workflow.
# Built by scripts/aks/16-deploy-fleet.ps1, which stages the build context (including the CLI binary, which is not
# part of this repository).
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash ca-certificates coreutils python3 socat \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 65532 fleet \
    && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin fleet

COPY openshell /usr/local/bin/openshell
COPY scripts/aks/agent-fleet.sh scripts/aks/run-agent.sh /opt/fleet/scripts/aks/
COPY deploy/aks/agents /opt/fleet/deploy/aks/agents
COPY deploy/aks/agent-sandbox-policy.yaml deploy/aks/agent-workflow.yml /opt/fleet/deploy/aks/
COPY deploy/aks/fleet/entrypoint.sh /opt/fleet/entrypoint.sh
RUN chmod 0755 /usr/local/bin/openshell /opt/fleet/entrypoint.sh /opt/fleet/scripts/aks/*.sh

USER 65532:65532
WORKDIR /opt/fleet
ENTRYPOINT ["/opt/fleet/entrypoint.sh"]
