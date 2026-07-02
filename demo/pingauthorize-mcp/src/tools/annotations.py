"""Annotation tools: attach and list findings on graph nodes.

Annotations are stored as :Annotation nodes linked to their target via ANNOTATED_WITH,
so they survive re-syncs of the policy tree (sync deletes policy nodes but callers should
re-attach; annotations are keyed independently and re-linked here on write)."""
from __future__ import annotations

VALID_TYPES = {"note", "warning", "error", "suggestion"}


def register(mcp, ctx, dump):
    graph = ctx.graph

    @mcp.tool()
    def annotate_node(node_id: str, node_type: str, annotation_type: str,
                      content: str, author: str = "") -> str:
        """Attach an annotation (note | warning | error | suggestion) to a graph node."""
        if annotation_type not in VALID_TYPES:
            raise ValueError(f"annotation_type must be one of {sorted(VALID_TYPES)}")
        rows = graph.query(
            f"""
            MATCH (target:{node_type} {{id:$node_id}})
            CREATE (a:Annotation {{
                id: randomUUID(), nodeId:$node_id, nodeType:$node_type,
                annotationType:$atype, content:$content, author:$author,
                createdAt: toString(datetime())
            }})
            MERGE (target)-[:ANNOTATED_WITH]->(a)
            RETURN a AS annotation
            """,
            {"node_id": node_id, "node_type": node_type, "atype": annotation_type,
             "content": content, "author": author or "unknown"},
        )
        if not rows:
            raise ValueError(f"no {node_type} node with id {node_id} to annotate")
        return dump(rows[0]["annotation"])

    @mcp.tool()
    def list_annotations(node_id: str = "", node_type: str = "",
                         annotation_type: str = "") -> str:
        """List annotations, optionally filtered by node_id, node_type, or annotation_type."""
        clauses, params = [], {}
        if node_id:
            clauses.append("a.nodeId = $node_id"); params["node_id"] = node_id
        if node_type:
            clauses.append("a.nodeType = $node_type"); params["node_type"] = node_type
        if annotation_type:
            clauses.append("a.annotationType = $atype"); params["atype"] = annotation_type
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = graph.query(f"MATCH (a:Annotation) {where} RETURN a AS annotation "
                           "ORDER BY a.createdAt DESC", params)
        return dump([r["annotation"] for r in rows])
