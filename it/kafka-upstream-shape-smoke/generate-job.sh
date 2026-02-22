#!/usr/bin/env bash
set -euo pipefail

job_name="${K8S_KAFKA_UPSTREAM_IT_JOB_NAME:-sidewhale-kafka-upstream-shape-it}"
namespace="${K8S_NAMESPACE:-sidewhale-system}"
image="${K8S_KAFKA_UPSTREAM_IT_IMAGE:-nicolaka/netshoot:latest}"
docker_host="${K8S_SIDEWHALE_DOCKER_HOST:-tcp://sidewhale:23750}"
container_name="${K8S_KAFKA_UPSTREAM_IT_CONTAINER_NAME:-kafka-upstream-shape-it}"

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
            - name: KAFKA_UPSTREAM_IT_CONTAINER_NAME
              value: "${container_name}"
          command: ["/bin/sh", "-ec"]
          args:
            - |
              set -euo pipefail

              apk add --no-cache jq curl tar >/dev/null 2>&1 || true
              hostport="\${DOCKER_HOST#tcp://}"
              base="http://\${hostport}"
              host="\${hostport%%:*}"

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
                    "CLUSTER_ID=4L6g3nShT-eMCtK--X86sw",
                    "KAFKA_NODE_ID=1",
                    "KAFKA_PROCESS_ROLES=broker,controller",
                    "KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9094",
                    "KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,BROKER://0.0.0.0:9093,CONTROLLER://0.0.0.0:9094,TC-0://kafka:19092",
                    "KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=BROKER:PLAINTEXT,PLAINTEXT:PLAINTEXT,CONTROLLER:PLAINTEXT,TC-0:PLAINTEXT",
                    "KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER",
                    "KAFKA_INTER_BROKER_LISTENER_NAME=BROKER",
                    "KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1",
                    "KAFKA_OFFSETS_TOPIC_NUM_PARTITIONS=1",
                    "KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1",
                    "KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1",
                    "KAFKA_LOG_FLUSH_INTERVAL_MESSAGES=9223372036854775807",
                    "KAFKA_GROUP_INITIAL_REBALANCE_DELAY_MS=0"
                  ],
                  ExposedPorts: {"9092/tcp": {}},
                  Entrypoint: ["sh", "-c", "while [ ! -f /tmp/testcontainers_start.sh ]; do sleep 0.1; done; /tmp/testcontainers_start.sh"],
                  HostConfig: {
                    PortBindings: {"9092/tcp": [{HostPort: "0"}]},
                    NetworkMode: "bridge"
                  },
                  NetworkingConfig: {
                    EndpointsConfig: {
                      bridge: {
                        Aliases: ["kafka"]
                      }
                    }
                  }
                }'
              )"

              create_out="\$(curl -sS -H 'Content-Type: application/json' -d "\${payload}" -w '\n%{http_code}' "\${base}/containers/create?name=\${KAFKA_UPSTREAM_IT_CONTAINER_NAME}")"
              create_code="\$(printf '%s\n' "\${create_out}" | tail -n1)"
              create_res="\$(printf '%s\n' "\${create_out}" | head -n -1)"
              if [ "\${create_code}" != "201" ]; then
                echo "create failed status=\${create_code} body=\${create_res}"
                exit 1
              fi

              cid="\$(printf '%s' "\${create_res}" | jq -r '.Id')"
              if [ -z "\${cid}" ] || [ "\${cid}" = "null" ]; then
                echo "create failed: \${create_res}"
                exit 1
              fi

              start_code="\$(curl -sS -X POST -o /dev/null -w '%{http_code}' "\${base}/containers/\${cid}/start")"
              if [ "\${start_code}" != "204" ]; then
                echo "start failed status=\${start_code}"
                exit 1
              fi

              host_port=""
              for i in \$(seq 1 90); do
                inspect="\$(curl -fsS "\${base}/containers/\${cid}/json")"
                running="\$(printf '%s' "\${inspect}" | jq -r '.State.Running')"
                host_port="\$(printf '%s' "\${inspect}" | jq -r '.NetworkSettings.Ports["9092/tcp"][0].HostPort // empty')"
                if [ "\${running}" = "true" ] && [ -n "\${host_port}" ]; then
                  break
                fi
                sleep 1
              done

              if [ -z "\${host_port}" ]; then
                echo "port mapping was not assigned"
                curl -sS "\${base}/containers/\${cid}/json" | jq .
                exit 1
              fi

              hostname="\$(curl -fsS "\${base}/containers/\${cid}/json" | jq -r '.Config.Hostname')"
              if [ -z "\${hostname}" ] || [ "\${hostname}" = "null" ]; then
                echo "container hostname unavailable"
                exit 1
              fi

              printf '%s\n' \
                '#!/bin/bash' \
                "export KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://\${host}:\${host_port},BROKER://\${hostname}:9093,TC-0://kafka:19092" \
                '/etc/kafka/docker/run' \
                > /tmp/testcontainers_start.sh
              chmod 0777 /tmp/testcontainers_start.sh
              tar -C /tmp -cf /tmp/testcontainers_start.tar testcontainers_start.sh

              put_code="\$(curl -sS -X PUT -o /tmp/put.out -w '%{http_code}' \
                -H 'Content-Type: application/x-tar' \
                --data-binary @/tmp/testcontainers_start.tar \
                "\${base}/containers/\${cid}/archive?path=/tmp")"
              if [ "\${put_code}" != "200" ]; then
                echo "archive put failed status=\${put_code} body=\$(cat /tmp/put.out)"
                exit 1
              fi

              for i in \$(seq 1 180); do
                logs="\$(curl -sS "\${base}/containers/\${cid}/logs?stdout=1&stderr=1&tail=300" || true)"
                if printf '%s' "\${logs}" | grep -q "Transitioning from RECOVERY to RUNNING"; then
                  echo "observed Kafka transition with upstream-shaped startup flow"
                  exit 0
                fi
                sleep 1
              done

              echo "did not observe Kafka transition with upstream-shaped startup flow"
              echo "===== container inspect ====="
              curl -sS "\${base}/containers/\${cid}/json" | jq . || true
              echo "===== startup script stat ====="
              exec_id="\$(curl -sS -H 'Content-Type: application/json' -d '{"AttachStdout":true,"AttachStderr":true,"Tty":false,"Cmd":["sh","-c","ls -l /tmp/testcontainers_start.sh; head -n 5 /tmp/testcontainers_start.sh; getent hosts kafka || true"]}' "\${base}/containers/\${cid}/exec" | jq -r '.Id // empty')"
              if [ -n "\${exec_id}" ]; then
                curl -sS -H 'Content-Type: application/json' -d '{"Detach":false,"Tty":false}' "\${base}/exec/\${exec_id}/start" || true
              fi
              echo "===== container logs ====="
              curl -sS "\${base}/containers/\${cid}/logs?stdout=1&stderr=1&tail=500" | tail -n 500 || true
              exit 1
YAML
