"""Stream processor — the front door of the autonomous demo.

Consumes payment-request events off a Kafka topic and, for each one, kicks off the
autonomous orchestration agent (which will CIBA-authorize Bob, then execute the payment).
No human is at a keyboard here — the trigger is the stream.

    Kafka topic  payment.requested
      { paymentId, debtorAccount, creditorAccount, amount, currency, initiatedBy }
        │
        ▼
    this processor  ──POST /process──▶  autonomous-agent

Env:
  KAFKA_BOOTSTRAP     Kafka bootstrap servers (host:port[,host:port])
  KAFKA_TOPIC         default: payment.requested
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
TOPIC = os.environ.get("KAFKA_TOPIC", "payment.requested")
GROUP = os.environ.get("KAFKA_GROUP", "stream-processor")
AGENT_URL = os.environ.get("AUTONOMOUS_AGENT_URL", "http://localhost:8000").rstrip("/")


def _consumer() -> KafkaConsumer:
    # Retry the initial connect — Kafka may still be coming up on first boot.
    for attempt in range(1, 31):
        try:
            return KafkaConsumer(
                TOPIC,
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


def _dispatch(payment: dict) -> None:
    """Hand the payment to the autonomous agent to authorize + execute."""
    pid = payment.get("paymentId", "?")
    log.info("payment %s → dispatching to autonomous agent (%s AUD %s→%s, initiatedBy=%s)",
             pid, payment.get("amount"), payment.get("debtorAccount"),
             payment.get("creditorAccount"), payment.get("initiatedBy"))
    try:
        r = httpx.post(f"{AGENT_URL}/process", json=payment, timeout=180.0)
        log.info("payment %s → agent responded %s: %s", pid, r.status_code, r.text[:300])
    except Exception as exc:  # noqa: BLE001
        log.error("payment %s → dispatch failed: %s", pid, exc)


def main() -> None:
    log.info("stream-processor starting: topic=%s group=%s agent=%s broker=%s",
             TOPIC, GROUP, AGENT_URL, BOOTSTRAP)
    consumer = _consumer()
    log.info("subscribed; waiting for payment events…")
    for msg in consumer:
        _dispatch(msg.value)


if __name__ == "__main__":
    main()
