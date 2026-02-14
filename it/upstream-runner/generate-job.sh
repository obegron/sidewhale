#!/usr/bin/env bash
set -euo pipefail

job_name="${K8S_UPSTREAM_JOB_NAME:-sidewhale-upstream-tests}"
namespace="${K8S_NAMESPACE:-sidewhale-system}"
image="${K8S_UPSTREAM_RUNNER_IMAGE:-sidewhale-test-runner}:${K8S_UPSTREAM_RUNNER_TAG:-dev}"
docker_host="${K8S_SIDEWHALE_DOCKER_HOST:-tcp://sidewhale:23750}"
upstream_task="${K8S_UPSTREAM_TASK:-:testcontainers:test}"
upstream_test_args="${K8S_UPSTREAM_TEST_ARGS---tests org.testcontainers.containers.ContainerStateTest}"
extra_gradle_args="${K8S_UPSTREAM_EXTRA_GRADLE_ARGS---rerun-tasks --max-workers=1 --no-daemon}"

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
            - name: TESTCONTAINERS_RYUK_DISABLED
              value: "true"
            - name: TESTCONTAINERS_CHECKS_DISABLE
              value: "true"
            - name: UPSTREAM_TC_FETCH_MODE
              value: "never"
            - name: UPSTREAM_TC_TASK
              value: "${upstream_task}"
            - name: UPSTREAM_TC_TEST_ARGS
              value: "${upstream_test_args}"
            - name: UPSTREAM_TC_EXTRA_GRADLE_ARGS
              value: "${extra_gradle_args}"
          volumeMounts:
            - name: workspace
              mountPath: /workspace
      volumes:
        - name: workspace
          emptyDir: {}
YAML
