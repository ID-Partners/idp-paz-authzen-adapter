"""PDP decision tools via the /governance-engine endpoint."""
from __future__ import annotations

from typing import Any


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def make_decision(domain: str = "", action: str = "", service: str = "",
                      attributes: Any = None) -> str:
        """Make an authorization decision via the JSON PDP API. Returns PERMIT or DENY."""
        return dump(pap.decide(domain, action, service, attributes or {}))

    @mcp.tool()
    def batch_decisions(requests: Any) -> str:
        """Make multiple authorization decisions in one call.

        `requests` is an array of {domain, action, service, attributes} objects.
        """
        return dump(pap.decide_batch(requests or []))
