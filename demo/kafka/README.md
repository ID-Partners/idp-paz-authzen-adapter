# kafka — single-node KRaft broker (staging only)

The stream backbone of the autonomous demo. One `apache/kafka` container acting as both
broker and controller (KRaft, no ZooKeeper), reachable ONLY on the Railway private network
as `kafka.railway.internal:9092` (no public domain). Storage is ephemeral by design — the
demo's topics (`payment.requested`, `account.opening.requested`) auto-create, and events
are transient triggers, not a system of record.

Deploy (staging):

    railway up demo/kafka --path-as-root --service kafka --environment staging --detach

Gotcha honoured in the Dockerfile: Railway's private network is IPv6-only, so the listeners
are host-less (`PLAINTEXT://:9092`) — Java's wildcard bind is dual-stack. An explicit
`0.0.0.0` would refuse `*.railway.internal` connections.
