#!/usr/bin/env bash
set -euo pipefail

context="${K8S_CONTEXT:-k3d-sidewhale-k8s}"
namespace="${K8S_NAMESPACE:-sidewhale-system}"
job_name="${K8S_KAFKA_IT_JOB_NAME:-sidewhale-kafka-listener-it}"
timeout="${K8S_KAFKA_IT_TIMEOUT:-600s}"

kubectl --context "${context}" -n "${namespace}" get svc sidewhale >/dev/null

sidewhale_host="${K8S_SIDEWHALE_DOCKER_HOST:-}"
if [ -z "${sidewhale_host}" ]; then
  endpoint_ip="$(kubectl --context "${context}" -n "${namespace}" get endpoints sidewhale -o jsonpath='{.subsets[0].addresses[0].ip}')"
  if [ -z "${endpoint_ip}" ]; then
    echo "failed to resolve sidewhale endpoint IP"
    exit 1
  fi
  sidewhale_host="tcp://${endpoint_ip}:23750"
fi

kubectl --context "${context}" -n "${namespace}" delete job "${job_name}" --ignore-not-found >/dev/null
K8S_KAFKA_IT_JOB_NAME="${job_name}" \
K8S_NAMESPACE="${namespace}" \
K8S_SIDEWHALE_DOCKER_HOST="${sidewhale_host}" \
./it/kafka-listener-smoke/generate-job.sh | kubectl --context "${context}" apply -f -

if ! kubectl --context "${context}" -n "${namespace}" wait --for=condition=complete "job/${job_name}" --timeout="${timeout}"; then
  kubectl --context "${context}" -n "${namespace}" logs -f "job/${job_name}" || true
  exit 1
fi

kubectl --context "${context}" -n "${namespace}" logs -f "job/${job_name}"
