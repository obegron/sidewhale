#!/usr/bin/env bash
set -euo pipefail

job_name="${K8S_KAFKA_LOG_IT_JOB_NAME:-sidewhale-kafka-log-it}"
namespace="${K8S_NAMESPACE:-sidewhale-system}"
image="${K8S_KAFKA_LOG_IT_IMAGE:-nicolaka/netshoot:latest}"
docker_host="${K8S_SIDEWHALE_DOCKER_HOST:-tcp://sidewhale:23750}"
container_name="${K8S_KAFKA_LOG_IT_CONTAINER_NAME:-kafka-it-log-smoke}"

cat <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${job_name}
  namespace: ${namespace}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 86400
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: runner
          image: ${image}
          imagePullPolicy: IfNotPresent
          env:
            - name: DOCKER_HOST
              value: "${docker_host}"
            - name: KAFKA_LOG_IT_CONTAINER_NAME
              value: "${container_name}"
          command: ["/bin/sh", "-ec"]
          args:
            - |
              set -euo pipefail

              apk add --no-cache jq >/dev/null 2>&1 || true
              hostport="\${DOCKER_HOST#tcp://}"
              base="http://\${hostport}"

              curl -fsS "\${base}/_ping" >/dev/null

              cleanup() {
                if [ -n "\${cid:-}" ]; then
                  curl -sS -X DELETE "\${base}/containers/\${cid}?force=1" >/dev/null || true
                fi
              }
              trap cleanup EXIT

              existing_id="\$(curl -sS "\${base}/containers/json?all=1" | jq -r '.[] | select((.Names // []) | index("/${container_name}")) | .Id' | head -n1 || true)"
              if [ -n "\${existing_id}" ] && [ "\${existing_id}" != "null" ]; then
                curl -sS -X DELETE "\${base}/containers/\${existing_id}?force=1" >/dev/null || true
              fi

              payload="\$(jq -cn '
                {
                  Image: "apache/kafka-native:3.8.0",
                  Env: [
                    "KAFKA_NODE_ID=1",
                    "KAFKA_PROCESS_ROLES=broker,controller",
                    "CLUSTER_ID=4L6g3nShT-eMCtK--X86sw",
                    "KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9094",
                    "KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,CONTROLLER://0.0.0.0:9094,BROKER://0.0.0.0:9093",
                    "KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka-it-log-smoke:9092,BROKER://kafka-it-log-smoke:9093",
                    "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=BROKER:PLAINTEXT,PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT",
                    "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER",
                    "KAFKA_INTER_BROKER_LISTENER_NAME=BROKER",
                    "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
                    "KAFKA_OFFSETS_TOPIC_NUM_PARTITIONS=1",
                    "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1",
                    "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1",
                    "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0"
                  ],
                  ExposedPorts: {"9092/tcp": {}},
                  HostConfig: {PortBindings: {"9092/tcp": [{HostPort: "0"}]}}
                }'
              )"

              create_res="\$(curl -fsS -H 'Content-Type: application/json' -d "\${payload}" "\${base}/containers/create?name=\${KAFKA_LOG_IT_CONTAINER_NAME}")"
              cid="\$(printf '%s' "\${create_res}" | jq -r '.Id')"
              if [ -z "\${cid}" ] || [ "\${cid}" = "null" ]; then
                echo "create failed: \${create_res}"
                exit 1
              fi
              curl -fsS -X POST "\${base}/containers/\${cid}/start" >/dev/null

              for i in \$(seq 1 120); do
                logs="\$(curl -sS "\${base}/containers/\${cid}/logs?stdout=1&stderr=1&tail=200" || true)"
                if printf '%s' "\${logs}" | grep -q "Transitioning from RECOVERY to RUNNING"; then
                  echo "observed Kafka lifecycle transition in sidewhale logs endpoint"
                  exit 0
                fi
                sleep 1
              done

              echo "did not observe expected Kafka lifecycle transition in sidewhale logs endpoint"
              curl -sS "\${base}/containers/\${cid}/logs?stdout=1&stderr=1&tail=300" | tail -n 300 || true
              exit 1
YAML
