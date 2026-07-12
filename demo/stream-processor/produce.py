"""Inject a test event onto Kafka — stands in for the upstream producer.

Payments (default):
  KAFKA_BOOTSTRAP=localhost:9092 AMOUNT=150 FROM=CHK-1001 TO=SAV-1002 python produce.py
Account opening:
  TYPE=opening CUSTOMER=alice ACCOUNT_TYPE=savings python produce.py
"""
import json
import os
import uuid

from kafka import KafkaProducer

BOOTSTRAP = os.environ.get("KAFKA_BOOTSTRAP", "localhost:9092")
KIND = os.environ.get("TYPE", "payment").lower()

if KIND in ("opening", "account_opening", "open"):
    topic = os.environ.get("KAFKA_TOPIC", "account.opening.requested")
    event = {
        "requestId": uuid.uuid4().hex[:12],
        "customerId": os.environ.get("CUSTOMER", "alice"),  # the ACCOUNT OWNER (bank customer id)
        "accountType": os.environ.get("ACCOUNT_TYPE", "savings"),
        "initiatedBy": os.environ.get("BY", "bob"),
    }
else:
    topic = os.environ.get("KAFKA_TOPIC", "payment.requested")
    event = {
        "paymentId": uuid.uuid4().hex[:12],
        "debtorAccount": os.environ.get("FROM", "CHK-1001"),
        "creditorAccount": os.environ.get("TO", "SAV-1002"),
        "amount": float(os.environ.get("AMOUNT", "150")),
        "currency": os.environ.get("CURRENCY", "AUD"),
        "initiatedBy": os.environ.get("BY", "bob"),
    }

producer = KafkaProducer(
    bootstrap_servers=BOOTSTRAP.split(","),
    value_serializer=lambda v: json.dumps(v).encode("utf-8"),
)
producer.send(topic, event)
producer.flush()
print("produced →", topic, ":", event)
