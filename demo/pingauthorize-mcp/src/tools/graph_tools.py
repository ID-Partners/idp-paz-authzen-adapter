"""Knowledge-graph tools: status, sync, and raw Cypher query."""
from __future__ import annotations

from typing import Any


def register(mcp, ctx, dump):
    graph = ctx.graph
    pap = ctx.pap

    @mcp.tool()
    def graph_status() -> str:
        """Report Neo4j connectivity plus per-label node counts and relationship counts."""
        return dump(graph.status())

    @mcp.tool()
    def sync_graph(branch_id: str) -> str:
        """Sync the PingAuthorize policy tree on a branch into the Neo4j knowledge graph.

        Fetches attributes, conditions, actions, statements, rules, policies, and policy
        sets from the PAP and upserts them (with relationships) into Neo4j. Run this before
        the analysis tools.
        """
        return dump(graph.sync(pap, ctx.branch(branch_id)))

    @mcp.tool()
    def query_graph(query: str, parameters: Any = None) -> str:
        """Run a read Cypher query against the knowledge graph and return the rows."""
        return dump(graph.query(query, parameters or {}))
