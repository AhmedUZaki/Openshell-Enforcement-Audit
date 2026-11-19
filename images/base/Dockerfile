# Minimal no-agent sandbox base image: plain Ubuntu plus iproute2, which
# OpenShell's supervisor requires inside the sandbox to set up its network
# namespace isolation (without it, sandbox creation fails with "trusted ip
# helper not found"). No agent, no LLM, no OpenClaw -- just a shell.
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd sandbox && useradd -m -g sandbox sandbox
