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

# Garak (NVIDIA's LLM vulnerability scanner) gets a virtual environment of its own: its dependencies are large and must not disturb the agent toolkit's. The CPU build of PyTorch
# is installed first so pip does not pull the multi-gigabyte GPU wheels. The red-team agent calls it as a tool; nothing else uses it.
RUN python3 -m venv /opt/garak     && /opt/garak/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu     && /opt/garak/bin/pip install --no-cache-dir garak

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
