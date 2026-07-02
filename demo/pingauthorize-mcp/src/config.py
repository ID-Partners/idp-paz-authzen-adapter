"""Runtime configuration, sourced from environment variables.

Mirrors the env contract of the original Go server so it is a drop-in replacement
inside the existing docker-compose stack.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Config:
    # PAP (Policy Administration Point) REST API
    pap_url: str = os.getenv("PINGAUTHORIZE_PAP_URL", "https://host.docker.internal:7443").rstrip("/")
    pap_auth_method: str = os.getenv("PINGAUTHORIZE_AUTH_METHOD", "header")
    pap_username: str = os.getenv("PINGAUTHORIZE_USERNAME", "admin")
    pap_password: str = os.getenv("PINGAUTHORIZE_PASSWORD", "")
    pap_verify_tls: bool = _bool("PINGAUTHORIZE_VERIFY_TLS", False)
    default_branch_id: str = os.getenv("PINGAUTHORIZE_BRANCH_ID", "")

    # PDP (decision endpoint). Defaults to the PAP host if unset.
    pdp_url: str = os.getenv("PINGAUTHORIZE_PDP_URL", "").rstrip("/")

    # Neo4j knowledge graph
    neo4j_uri: str = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
    neo4j_username: str = os.getenv("NEO4J_USERNAME", "neo4j")
    neo4j_password: str = os.getenv("NEO4J_PASSWORD", "changeme")
    neo4j_database: str = os.getenv("NEO4J_DATABASE", "neo4j")

    # MCP HTTP server
    http_host: str = os.getenv("MCP_HTTP_HOST", "0.0.0.0")
    http_port: int = int(os.getenv("MCP_HTTP_PORT", "8080"))

    def resolved_pdp_url(self) -> str:
        return self.pdp_url or self.pap_url


CONFIG = Config()
