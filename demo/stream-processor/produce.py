"""Inject a test payment.requested event onto Kafka — stands in for the upstream producer.

  KAFKA_BOOTSTRAP=localhost:9092 AMOUNT=150 FROM=CHK-1001 TO=SAV-1002 python produce.py
"""
import json
import os
import uuid

from kafka import KafkaProducer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
TOPIC = os.environ.get("KAFKA_TOPIC", "payment.requested")

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP.split(","),
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)
event = {
    "paymentId": uuid.uuid4().hex[:12],
    "debtorAccount": os.environ.get("FROM", "CHK-1001"),
    "creditorAccount": os.environ.get("TO", "SAV-1002"),
    "amount": float(os.environ.get("AMOUNT", "150")),
    "currency": os.environ.get("CURRENCY", "AUD"),
    "initiatedBy": os.environ.get("BY", "bob"),
}
producer.send(TOPIC, event)
producer.flush()
print("produced →", TOPIC, ":", event)
