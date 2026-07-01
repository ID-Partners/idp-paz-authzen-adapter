"""
Amazon Bedrock AgentCore Runtime entrypoint.

Use this when deploying to AWS AgentCore Runtime (rather than Railway). It wraps
the same `run_agent()` used by the Railway HTTP host in the `bedrock-agentcore`
SDK, which provides the /invocations + /ping server and integrates with
AgentCore Identity, Memory, and Observability.

Deploy with the AgentCore starter toolkit, e.g.:

    pip install bedrock-agentcore bedrock-agentcore-starter-toolkit
    agentcore configure --entrypoint agentcore_entrypoint.py
    agentcore launch

Requires: bedrock-agentcore (see requirements-agentcore.txt).
"""
from __future__ import annotations

import asyncio

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from agent_core import run_agent

app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload):
    prompt = payload.get("prompt") or payload.get("message") or ""
    session_id = payload.get("session_id", "demo")
    return asyncio.run(run_agent(prompt, session_id))


if __name__ == "__main__":
    app.run()
