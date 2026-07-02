"""Graph-analysis tools.

These run Cypher over the synced knowledge graph (run sync_graph first). The queries
follow the shapes recovered from the original server's embedded Cypher.
"""
from __future__ import annotations

from typing import Any


def register(mcp, ctx, dump):
    graph = ctx.graph

    @mcp.tool()
    def find_authorization_paths(subject_type: str = "", resource_type: str = "",
                                 action_name: str = "") -> str:
        """Trace policy-set -> policy -> rule paths that can authorize a resource/action."""
        rows = graph.query(
            """
            MATCH path = (ps:PolicySet)-[:CONTAINS_POLICY]->(p:Policy)-[:HAS_RULE]->(r:Rule)
            OPTIONAL MATCH (r)-[:REFERENCES_ATTRIBUTE]->(a:Attribute)
            RETURN ps.name AS policySet, p.name AS policy, p.combiningAlgorithm AS combiningAlgorithm,
                   r.name AS rule, r.effect AS effect, collect(DISTINCT a.name) AS attributes
            ORDER BY policySet, policy, rule
            """)
        return dump({"paths": rows, "filters": {
            "subject_type": subject_type, "resource_type": resource_type,
            "action_name": action_name}})

    @mcp.tool()
    def detect_toxic_combinations(resource_type: str = "") -> str:
        """Find permit rules that grant access to sensitive resources without a guarding condition."""
        rows = graph.query(
            """
            MATCH (p:Policy)-[:HAS_RULE]->(r:Rule {effect:"permit"})
            OPTIONAL MATCH (r)-[:HAS_CONDITION]->(c:Condition)
            OPTIONAL MATCH (r)-[:REFERENCES_ATTRIBUTE]->(a:Attribute)
            WITH p, r, count(c) AS conds, collect(DISTINCT a.name) AS attrs
            RETURN p.name AS policy, r.name AS rule, conds AS conditionCount,
                   attrs AS attributes,
                   CASE WHEN conds = 0 THEN "HIGH" ELSE "LOW" END AS severity
            ORDER BY severity DESC, policy, rule
            """)
        return dump({"resource_type": resource_type, "findings": rows})

    @mcp.tool()
    def detect_rule_conflicts(policy_name: str = "", include_disabled: bool = False) -> str:
        """Find permit/deny rule pairs in the same policy with overlapping conditions.

        Severity: HIGH if either rule is unconditional, MEDIUM if they share attributes,
        LOW if they only share named conditions.
        """
        rows = graph.query(
            """
            MATCH (p:Policy)-[:HAS_RULE]->(r1:Rule {effect:"permit"})
            MATCH (p)-[:HAS_RULE]->(r2:Rule {effect:"deny"})
            OPTIONAL MATCH (r1)-[:REFERENCES_ATTRIBUTE]->(a:Attribute)<-[:REFERENCES_ATTRIBUTE]-(r2)
            OPTIONAL MATCH (r1)-[:HAS_CONDITION]->(c1:Condition)
            OPTIONAL MATCH (r2)-[:HAS_CONDITION]->(c2:Condition)
            WITH p, r1, r2, collect(DISTINCT a.name) AS sharedAttrs,
                 count(c1) = 0 OR count(c2) = 0 AS hasUnconditional
            WHERE ($policyName = "" OR p.name = $policyName)
            RETURN p.name AS policy, r1.name AS permitRule, r2.name AS denyRule,
                   sharedAttrs,
                   CASE WHEN hasUnconditional THEN "HIGH"
                        WHEN size(sharedAttrs) > 0 THEN "MEDIUM"
                        ELSE "LOW" END AS severity
            ORDER BY severity DESC, policy
            """, {"policyName": policy_name})
        return dump({"conflicts": rows})

    @mcp.tool()
    def find_rules_by_effect(effect: str, attribute_filter: str = "") -> str:
        """List all rules with a given effect (permit/deny), optionally referencing an attribute."""
        cypher = """
            MATCH (p:Policy)-[:HAS_RULE]->(r:Rule {effect:$effect})
            OPTIONAL MATCH (r)-[:REFERENCES_ATTRIBUTE]->(a:Attribute)
            WITH p, r, collect(DISTINCT a.name) AS attrs
            WHERE $attr = "" OR $attr IN attrs
            RETURN p.name AS policy, r.name AS rule, r.effect AS effect, attrs AS attributes
            ORDER BY policy, rule
            """
        return dump(graph.query(cypher, {"effect": effect, "attr": attribute_filter}))

    @mcp.tool()
    def find_attribute_dependencies(attribute_name: str) -> str:
        """Find rules, conditions, and value processors that depend on an attribute."""
        rows = graph.query(
            """
            MATCH (a:Attribute {name:$name})
            OPTIONAL MATCH (r:Rule)-[:REFERENCES_ATTRIBUTE]->(a)
            OPTIONAL MATCH (a)-[:USES_VALUE_PROCESSOR]->(vp:ValueProcessor)
            RETURN a.name AS attribute, a.id AS attributeId,
                   collect(DISTINCT r.name) AS referencingRules,
                   collect(DISTINCT vp.id) AS valueProcessors
            """, {"name": attribute_name})
        return dump(rows[0] if rows else {"attribute": attribute_name, "found": False})

    @mcp.tool()
    def find_condition_dependencies(condition_name: str) -> str:
        """Find rules and policies that reference a named condition."""
        rows = graph.query(
            """
            MATCH (c:Condition {name:$name})
            OPTIONAL MATCH (n)-[:REFERENCES_CONDITION]->(c)
            RETURN c.name AS condition, c.id AS conditionId,
                   collect(DISTINCT {type: head(labels(n)), name: n.name}) AS referencedBy
            """, {"name": condition_name})
        return dump(rows[0] if rows else {"condition": condition_name, "found": False})

    @mcp.tool()
    def explain_decision_path(rule_name: str = "", rule_id: str = "",
                              policy_name: str = "") -> str:
        """Explain how a rule sits in the policy tree: its policy, effect, and attributes."""
        rows = graph.query(
            """
            MATCH (p:Policy)-[:HAS_RULE]->(r:Rule)
            WHERE ($ruleId <> "" AND r.id = $ruleId)
               OR ($ruleName <> "" AND r.name = $ruleName)
               OR ($policyName <> "" AND p.name = $policyName)
            OPTIONAL MATCH (r)-[:HAS_CONDITION]->(c:Condition)
            OPTIONAL MATCH (r)-[:REFERENCES_ATTRIBUTE]->(a:Attribute)
            RETURN p.name AS policy, p.combiningAlgorithm AS combiningAlgorithm,
                   r.name AS rule, r.effect AS effect,
                   collect(DISTINCT c.name) AS conditions,
                   collect(DISTINCT a.name) AS attributes
            """, {"ruleId": rule_id, "ruleName": rule_name, "policyName": policy_name})
        return dump({"paths": rows})

    @mcp.tool()
    def suggest_missing_deny_rules(policy_name: str) -> str:
        """Suggest deny rules for actions that only have permit coverage in a policy."""
        rows = graph.query(
            """
            MATCH (p:Policy {name:$policyName})-[:HAS_RULE]->(r:Rule)
            WITH p, collect(DISTINCT r.effect) AS effects
            RETURN p.name AS policy, effects,
                   NOT ("deny" IN effects) AS missesDeny,
                   p.combiningAlgorithm AS combiningAlgorithm
            """, {"policyName": policy_name})
        suggestions = []
        for row in rows:
            if row.get("missesDeny"):
                suggestions.append({
                    "policy": row["policy"],
                    "suggestion": "Policy has only permit rules; add a default-deny rule or "
                                  "use a DenyUnlessPermit combining algorithm to avoid failing open.",
                    "combiningAlgorithm": row.get("combiningAlgorithm"),
                })
        return dump({"policy": policy_name, "analysis": rows, "suggestions": suggestions})

    @mcp.tool()
    def check_policy_completeness(resource_type: str = "", action_name: str = "") -> str:
        """Check whether policies cover both permit and deny paths for their actions."""
        rows = graph.query(
            """
            MATCH (p:Policy)-[:HAS_RULE]->(r:Rule)
            WITH p, collect(DISTINCT r.effect) AS effects, count(r) AS ruleCount
            RETURN p.name AS policy, p.combiningAlgorithm AS combiningAlgorithm,
                   ruleCount, effects,
                   ("permit" IN effects) AS hasPermit, ("deny" IN effects) AS hasDeny
            ORDER BY policy
            """)
        gaps = [r for r in rows if not (r.get("hasPermit") and r.get("hasDeny"))]
        return dump({"resource_type": resource_type, "action_name": action_name,
                     "policies": rows, "potentialGaps": gaps})
