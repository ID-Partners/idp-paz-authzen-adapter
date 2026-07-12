# Kafka broker for the autonomous demo — single-node KRaft (no ZooKeeper), staging-only.
#
# Official Apache Kafka image, configured entirely via env. One container is both broker
# and controller. Storage is ephemeral (no volume): topics auto-create on demand, and a
# redeploy simply starts a fresh log — fine for a demo stream, nothing durable lives here.
FROM apache/kafka:3.9.1

# KRaft single node: this container is broker AND controller.
ENV KAFKA_NODE_ID=1 \
    KAFKA_PROCESS_ROLES=broker,controller \
    KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9093 \
    KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
    # Host-less listeners bind the Java wildcard socket, which is DUAL-STACK (v4+v6).
    # Railway's private network (*.railway.internal) is IPv6-only, so an explicit
    # 0.0.0.0 bind would refuse internal connections — same class of bug as the
    # event-sink PORT/bind gotchas.
    KAFKA_LISTENERS=PLAINTEXT://:9092,CONTROLLER://:9093 \
    # What clients are told to connect to: the Railway-internal DNS name.
    KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka.railway.internal:9092 \
    KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT \
    # Demo conveniences: auto-create topics, single-replica internals, small heap.
    KAFKA_AUTO_CREATE_TOPICS_ENABLE=true \
    KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 \
    KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
    KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 \
    KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0 \
    KAFKA_HEAP_OPTS="-Xmx512m -Xms256m"

EXPOSE 9092
