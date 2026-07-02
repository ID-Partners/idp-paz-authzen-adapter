"""Snapshot import / export / merge tools."""
from __future__ import annotations

from typing import Any


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def export_snapshot(snapshot_id: str, entities: Any = None) -> str:
        """Export a snapshot's entities as portable JSON."""
        return dump(pap.export_snapshot(snapshot_id, entities))

    @mcp.tool()
    def import_snapshot(branch_name: str, snapshot_data: Any) -> str:
        """Import snapshot data into a (new) branch by name."""
        return dump(pap.import_snapshot(branch_name, snapshot_data))

    @mcp.tool()
    def merge_snapshot(branch_name: str, snapshot_data: Any,
                       conflict_resolutions: Any = None) -> str:
        """Merge snapshot data into a branch, applying any conflict resolutions."""
        return dump(pap.merge_snapshot(branch_name, snapshot_data, conflict_resolutions))
