"""Neo4j knowledge-graph layer.

Mirrors the PingAuthorize policy tree into Neo4j so the analysis tools can reason
about it with Cypher. Node labels and relationship types match the original server
(recovered from its embedded Cypher — see reference/API.md):

  Nodes: Policy, PolicySet, Rule, Condition, Attribute, Action, Statement,
         ValueProcessor, Annotation
  Rels:  CONTAINS_POLICY, CONTAINS_POLICY_SET, HAS_RULE, HAS_CONDITION,
         HAS_STATEMENT, HAS_TARGET, REFERENCES_ATTRIBUTE, REFERENCES_CONDITION,
         REFERENCES_ACTION, USES_VALUE_PROCESSOR, ANNOTATED_WITH
"""
from __future__ import annotations

from typing import Any

from neo4j import GraphDatabase

from .config import Config
from .pap_client import (
    PAPClient, PM_POLICIES, PM_RULES, PM_POLICY_SETS, PM_STATEMENTS,
    TF_ATTRIBUTES, TF_CONDITIONS, TF_ACTIONS,
)

NODE_LABELS = ["Action", "Annotation", "Attribute", "Condition", "Policy",
               "PolicySet", "Rule", "Statement", "ValueProcessor"]
REL_TYPES = ["ANNOTATED_WITH", "CONTAINS_POLICY", "CONTAINS_POLICY_SET",
             "HAS_CONDITION", "HAS_RULE", "HAS_STATEMENT", "HAS_TARGET",
             "REFERENCES_ACTION", "REFERENCES_ATTRIBUTE", "REFERENCES_CONDITION",
             "USES_VALUE_PROCESSOR"]


def _effect_of(rule: dict) -> str:
    """Normalise a rule's effectSettings into a 'permit'/'deny' label."""
    es = rule.get("effectSettings") or {}
    t = (es.get("type") or "").lower()
    if "deny" in t and "permit" not in t:
        return "deny"
    if "permit" in t and "deny" not in t:
        return "permit"
    # conditional*: name reflects the primary effect (permitElseDeny -> permit)
    if t.startswith("conditionalpermit"):
        return "permit"
    if t.startswith("conditionaldeny"):
        return "deny"
    return t or "unknown"


def _walk_condition_refs(cond: Any, attr_ids: set, cond_ids: set, action_names: set) -> None:
    """Collect attribute / named-condition / action references from a condition tree."""
    if not isinstance(cond, dict):
        return
    for key, body in cond.items():
        if key == "comparison" and isinstance(body, dict):
            for side in ("left", "right"):
                operand = body.get(side) or {}
                if "attribute" in operand:
                    aid = operand["attribute"].get("id")
                    if aid:
                        attr_ids.add(aid)
        elif key in ("and", "or") and isinstance(body, dict):
            for sub in body.get("conditions", []):
                _walk_condition_refs(sub, attr_ids, cond_ids, action_names)
        elif key == "reference" and isinstance(body, dict):
            cid = body.get("id")
            if cid:
                cond_ids.add(cid)


class GraphStore:
    def __init__(self, cfg: Config):
        self._cfg = cfg
        self._driver = GraphDatabase.driver(
            cfg.neo4j_uri, auth=(cfg.neo4j_username, cfg.neo4j_password))

    def close(self) -> None:
        self._driver.close()

    def _session(self):
        return self._driver.session(database=self._cfg.neo4j_database)

    # ---- generic ----------------------------------------------------------
    def query(self, cypher: str, parameters: dict | None = None) -> list[dict]:
        with self._session() as s:
            return [r.data() for r in s.run(cypher, parameters or {})]

    def status(self) -> dict:
        node_counts: dict[str, int] = {}
        rel_counts: dict[str, int] = {}
        connected = True
        try:
            with self._session() as s:
                for label in NODE_LABELS:
                    rec = s.run(f"MATCH (n:{label}) RETURN count(n) AS c").single()
                    node_counts[label] = rec["c"] if rec else 0
                for rel in REL_TYPES:
                    rec = s.run(f"MATCH ()-[r:{rel}]->() RETURN count(r) AS c").single()
                    rel_counts[rel] = rec["c"] if rec else 0
        except Exception:
            connected = False
        return {
            "connected": connected,
            "database": self._cfg.neo4j_database,
            "node_counts": node_counts,
            "relationship_counts": rel_counts,
            "total_nodes": sum(node_counts.values()),
            "total_relationships": sum(rel_counts.values()),
        }

    def ensure_constraints(self) -> None:
        stmts = [
            f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE"
            for label in NODE_LABELS if label != "Action"
        ]
        stmts.append("CREATE CONSTRAINT IF NOT EXISTS FOR (a:Action) REQUIRE a.id IS UNIQUE")
        with self._session() as s:
            for st in stmts:
                try:
                    s.run(st)
                except Exception:
                    pass

    # ---- sync -------------------------------------------------------------
    def sync(self, pap: PAPClient, branch_id: str) -> dict:
        """Fetch the policy tree from the PAP and upsert it into Neo4j.

        Returns per-entity counts. Idempotent: nodes/rels are MERGEd by id.
        """
        self.ensure_constraints()
        counts: dict[str, int] = {}

        def data(listing: Any) -> list[dict]:
            if isinstance(listing, dict):
                return listing.get("data", []) or []
            return listing or []

        attributes = data(pap.tf_list(TF_ATTRIBUTES, branch_id))
        conditions = data(pap.tf_list(TF_CONDITIONS, branch_id))
        actions = data(pap.tf_list(TF_ACTIONS, branch_id))
        policies = data(pap.pm_list(PM_POLICIES, branch_id))
        rules = data(pap.pm_list(PM_RULES, branch_id))
        policy_sets = data(pap.pm_list(PM_POLICY_SETS, branch_id))
        statements = data(pap.pm_list(PM_STATEMENTS, branch_id))

        with self._session() as s:
            # wipe branch-scoped graph so sync reflects current state
            s.run("MATCH (n) DETACH DELETE n")

            for a in attributes:
                s.run(
                    "MERGE (n:Attribute {id:$id}) SET n.name=$name, n.fullName=$full, "
                    "n.valueType=$vt, n.category=$cat",
                    id=a.get("id"), name=a.get("name"), full=a.get("fullName"),
                    vt=a.get("valueType"), cat=(a.get("properties") or {}).get("category"))
                vp = a.get("valueProcessor")
                if isinstance(vp, dict) and vp.get("id"):
                    s.run("MERGE (v:ValueProcessor {id:$vid}) SET v.type=$t "
                          "WITH v MATCH (a:Attribute {id:$aid}) MERGE (a)-[:USES_VALUE_PROCESSOR]->(v)",
                          vid=vp.get("id"), t=vp.get("type"), aid=a.get("id"))
            counts["attributes"] = len(attributes)

            for c in conditions:
                s.run("MERGE (n:Condition {id:$id}) SET n.name=$name",
                      id=c.get("id"), name=c.get("name"))
            counts["conditions"] = len(conditions)

            for a in actions:
                s.run("MERGE (n:Action {id:$id}) SET n.name=$name",
                      id=a.get("id"), name=a.get("name"))
            counts["actions"] = len(actions)

            for st in statements:
                s.run("MERGE (n:Statement {id:$id}) SET n.name=$name",
                      id=st.get("id"), name=st.get("name"))
            counts["statements"] = len(statements)

            for r in rules:
                s.run("MERGE (n:Rule {id:$id}) SET n.name=$name, n.effect=$effect",
                      id=r.get("id"), name=r.get("name"), effect=_effect_of(r))
                self._link_condition_refs(s, "Rule", r.get("id"), r.get("condition"))
                es = r.get("effectSettings") or {}
                if isinstance(es.get("condition"), dict):
                    self._link_condition_refs(s, "Rule", r.get("id"), es.get("condition"))
            counts["rules"] = len(rules)

            for p in policies:
                s.run("MERGE (n:Policy {id:$id}) SET n.name=$name, n.combiningAlgorithm=$ca",
                      id=p.get("id"), name=p.get("name"),
                      ca=(p.get("combiningAlgorithm") or {}).get("algorithm"))
                for child in p.get("children", []) or []:
                    cid = child.get("id") if isinstance(child, dict) else child
                    s.run("MATCH (p:Policy {id:$pid}) MATCH (r:Rule {id:$rid}) "
                          "MERGE (p)-[:HAS_RULE]->(r)", pid=p.get("id"), rid=cid)
                self._link_condition_refs(s, "Policy", p.get("id"), p.get("condition"), target=True)
            counts["policies"] = len(policies)

            for ps in policy_sets:
                s.run("MERGE (n:PolicySet {id:$id}) SET n.name=$name, n.combiningAlgorithm=$ca",
                      id=ps.get("id"), name=ps.get("name"),
                      ca=(ps.get("combiningAlgorithm") or {}).get("algorithm"))
                for child in ps.get("children", []) or []:
                    cid = child.get("id") if isinstance(child, dict) else child
                    # child may be a Policy or a PolicySet
                    s.run("MATCH (ps:PolicySet {id:$pid}) MATCH (p:Policy {id:$cid}) "
                          "MERGE (ps)-[:CONTAINS_POLICY]->(p)", pid=ps.get("id"), cid=cid)
                    s.run("MATCH (ps:PolicySet {id:$pid}) MATCH (c:PolicySet {id:$cid}) "
                          "MERGE (ps)-[:CONTAINS_POLICY_SET]->(c)", pid=ps.get("id"), cid=cid)
            counts["policy_sets"] = len(policy_sets)

        return {"branch_id": branch_id, "synced": counts}

    @staticmethod
    def _link_condition_refs(session, label: str, node_id: str, cond: Any,
                             target: bool = False) -> None:
        if not node_id or not isinstance(cond, dict):
            return
        attr_ids: set = set()
        cond_ids: set = set()
        action_names: set = set()
        _walk_condition_refs(cond, attr_ids, cond_ids, action_names)
        for aid in attr_ids:
            session.run(
                f"MATCH (n:{label} {{id:$nid}}) MATCH (a:Attribute {{id:$aid}}) "
                "MERGE (n)-[:REFERENCES_ATTRIBUTE]->(a)", nid=node_id, aid=aid)
        for cid in cond_ids:
            session.run(
                f"MATCH (n:{label} {{id:$nid}}) MATCH (c:Condition {{id:$cid}}) "
                "MERGE (n)-[:REFERENCES_CONDITION]->(c)", nid=node_id, cid=cid)
