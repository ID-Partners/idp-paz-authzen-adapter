"""MCP server entry point.

Reimplementation of ``idpartners-pingauthorize-mcp-server`` (server name
``pingauthorize-policy-manager``) in Python on top of the official MCP SDK's
FastMCP, served over streamable HTTP at ``/mcp`` to match the original transport.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from mcp.server.fastmcp import FastMCP

from .config import CONFIG, Config
from .graph_store import GraphStore
from .pap_client import PAPClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("pingauthorize-mcp")


@dataclass
class Context:
    cfg: Config
    pap: PAPClient
    graph: GraphStore

    def branch(self, branch_id: str | None) -> str:
        b = branch_id or self.cfg.default_branch_id
        if not b:
            raise ValueError("branch_id is required (no PINGAUTHORIZE_BRANCH_ID default set)")
        return b


def build_context() -> Context:
    pap = PAPClient(CONFIG)
    graph = GraphStore(CONFIG)
    return Context(cfg=CONFIG, pap=pap, graph=graph)


def dump(obj: Any) -> str:
    """Uniform text payload for tool results (matches the Go server's JSON text)."""
    if isinstance(obj, str):
        return obj
    return json.dumps(obj, indent=2, default=str)


def create_server() -> FastMCP:
    ctx = build_context()
    mcp = FastMCP(
        name="pingauthorize-policy-manager",
        host=CONFIG.http_host,
        port=CONFIG.http_port,
        streamable_http_path="/mcp",
    )

    # Register every tool group. Each module exposes register(mcp, ctx, dump).
    from .tools import (
        branches, trust_framework, policies, rules, policy_sets,
        decisions, snapshots, test_suites, graph_tools, analysis, annotations,
    )
    for mod in (branches, trust_framework, policies, rules, policy_sets,
                decisions, snapshots, test_suites, graph_tools, analysis, annotations):
        mod.register(mcp, ctx, dump)

    log.info("Registered PingAuthorize policy-manager tools; PAP=%s Neo4j=%s",
             CONFIG.pap_url, CONFIG.neo4j_uri)
    return mcp


def main() -> None:
    mcp = create_server()
    log.info("Starting MCP streamable-HTTP server on %s:%d/mcp",
             CONFIG.http_host, CONFIG.http_port)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()
