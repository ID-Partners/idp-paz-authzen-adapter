# stream-processor
Consumes `payment.requested` from Kafka and POSTs each event to the autonomous agent's
`/process`. Env: `KAFKA_BOOTSTRAP`, `KAFKA_TOPIC` (default payment.requested), `KAFKA_GROUP`,
`AUTONOMOUS_AGENT_URL`. Inject a test event with `produce.py`.
