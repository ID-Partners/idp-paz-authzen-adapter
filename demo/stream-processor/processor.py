"""Stream processor — the front door of the autonomous demo.

Consumes banking-operation events off Kafka and, for each one, kicks off the autonomous
orchestration agent (which gets Bob — the bank staff member who owns the agent — to
authorize the operation, then drives the same concierge → task-agent chain as the
interactive demo). No human is at a keyboard here — the trigger is the stream.

    Kafka topic  payment.requested
      { paymentId, debtorAccount, creditorAccount, amount, currency, initiatedBy }
    Kafka topic  account.opening.requested
      { requestId, customerId, accountType, initiatedBy }
        │
        ▼
    this processor  ──POST /process (+ eventType)──▶  autonomous-agent

Env:
  KAFKA_BOOTSTRAP     Kafka bootstrap servers (host:port[,host:port])
  KAFKA_TOPICS        comma list; default: payment.requested,account.opening.requested
  KAFKA_GROUP         default: stream-processor
  AUTONOMOUS_AGENT_URL  base URL of the autonomous agent (e.g. http://autonomous-agent:8000)
"""
from __future__ import annotations

import json
import logging
import os
import time

import httpx
from kafka import KafkaConsumer  # kafka-python

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("stream-processor")

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
# Both autonomous operations ride the stream; KAFKA_TOPIC kept as a legacy single-topic override.
TOPICS = [t.strip() for t in os.environ.get(
    "KAFKA_TOPICS",
    os.environ.get("KAFKA_TOPIC", "payment.requested,account.opening.requested"),
).split(",") if t.strip()]
GROUP = os.environ.get("KAFKA_GROUP", "stream-processor")
AGENT_URL = os.environ.get("AUTONOMOUS_AGENT_URL", "http://localhost:8000").rstrip("/")

# topic → the eventType label the orchestrator dispatches on
EVENT_TYPES = {"payment.requested": "payment", "account.opening.requested": "account_opening"}


def _consumer() -> KafkaConsumer:
    # Retry the initial connect — Kafka may still be coming up on first boot.
    for attempt in range(1, 31):
        try:
            return KafkaConsumer(
                *TOPICS,
                bootstrap_servers=BOOTSTRAP.split(","),
                group_id=GROUP,
                enable_auto_commit=True,
                auto_offset_reset="earliest",
                value_deserializer=lambda b: json.loads(b.decode("utf-8")),
            )
        except Exception as exc:  # noqa: BLE001
            log.warning("kafka connect attempt %d failed: %s", attempt, exc)
            time.sleep(3)
    raise SystemExit("could not connect to Kafka")


def _dispatch(topic: str, event: dict) -> None:
    """Hand the operation to the autonomous agent to get authorized + executed."""
    etype = EVENT_TYPES.get(topic, "payment")
    eid = event.get("paymentId") or event.get("requestId") or "?"
    log.info("%s %s → dispatching to autonomous agent (%s)", etype, eid,
             {k: v for k, v in event.items() if k != "eventType"})
    try:
        r = httpx.post(f"{AGENT_URL}/process", json={**event, "eventType": etype},
                       timeout=300.0)
        log.info("%s %s → agent responded %s: %s", etype, eid, r.status_code, r.text[:300])
    except Exception as exc:  # noqa: BLE001
        log.error("%s %s → dispatch failed: %s", etype, eid, exc)


def main() -> None:
    log.info("stream-processor starting: topics=%s group=%s agent=%s broker=%s",
             TOPICS, GROUP, AGENT_URL, BOOTSTRAP)
    consumer = _consumer()
    log.info("subscribed; waiting for events…")
    for msg in consumer:
        _dispatch(msg.topic, msg.value)


if __name__ == "__main__":
    main()
