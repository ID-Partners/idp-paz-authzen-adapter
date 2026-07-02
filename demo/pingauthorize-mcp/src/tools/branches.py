"""Version-control tools: branches and snapshot lifecycle."""
from __future__ import annotations


def register(mcp, ctx, dump):
    pap = ctx.pap

    @mcp.tool()
    def list_branches() -> str:
        """List all policy branches. Call this first to obtain a branch_id."""
        return dump(pap.list_branches())

    @mcp.tool()
    def get_branch(branch_id: str) -> str:
        """Get a single branch by ID, including its head/tip commit state."""
        return dump(pap.get_branch(ctx.branch(branch_id)))

    @mcp.tool()
    def create_branch(name: str, parent_branch_id: str) -> str:
        """Create a new branch off a parent branch."""
        return dump(pap.create_branch(name, parent_branch_id))

    @mcp.tool()
    def list_snapshots(branch_id: str) -> str:
        """List all snapshots (commits) on a branch."""
        return dump(pap.list_snapshots(ctx.branch(branch_id)))

    @mcp.tool()
    def create_snapshot(branch_id: str, message: str) -> str:
        """Create a snapshot (commit) of the current branch state."""
        return dump(pap.create_snapshot(ctx.branch(branch_id), message))
