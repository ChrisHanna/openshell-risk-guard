# Workload image for the NeMo Agent Toolkit demo agent. Built on top of the demo's
# workload image so the OpenShell supervisor's runtime dependencies are already present.
ARG BASE=risk-guard-demo/workload:55bf78645
FROM ${BASE}

USER root
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/agent \
    && /opt/agent/bin/pip install --no-cache-dir "nvidia-nat[langchain]" nemoguardrails

COPY rg_demo_agent /opt/agent-src/rg_demo_agent
COPY pyproject.toml /opt/agent-src/pyproject.toml
COPY workflow.yml /opt/agent-src/workflow.yml
COPY guardrails /opt/agent-src/guardrails
RUN /opt/agent/bin/pip install --no-cache-dir /opt/agent-src \
    && chown -R 1000:1000 /sandbox

USER 1000:1000
WORKDIR /sandbox
ENV PATH=/opt/agent/bin:$PATH
CMD ["/bin/bash"]
