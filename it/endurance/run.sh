#!/usr/bin/env bash
set -euo pipefail

BACKENDS_RAW="${ENDURANCE_BACKENDS:-proot,k8s}"
TASKS_RAW="${ENDURANCE_TASKS:-:testcontainers-postgresql:test,:testcontainers-ldap:test,testcontainers-kafka:test,:testcontainers-mockserver:test,testcontainers-mssql:test}"
ITERATIONS="${ENDURANCE_ITERATIONS:-100}"
REPORT_PATH="${ENDURANCE_REPORT:-/tmp/sidewhale-endurance-report.tsv}"
K8S_RESET="${ENDURANCE_K8S_RESET:-false}"
K8S_RESET_MODE="${ENDURANCE_K8S_RESET_MODE:-namespace}"
K8S_BUILD_IMAGE="${ENDURANCE_K8S_BUILD_IMAGE:-true}"
K8S_PREPULL_IMAGES_RAW="${ENDURANCE_K8S_PREPULL_IMAGES:-}"

if ! [[ "$ITERATIONS" =~ ^[0-9]+$ ]] || [ "$ITERATIONS" -le 0 ]; then
  echo "ENDURANCE_ITERATIONS must be a positive integer (got: $ITERATIONS)" >&2
  exit 1
fi

IFS=',' read -r -a BACKENDS <<<"$BACKENDS_RAW"
IFS=',' read -r -a TASKS <<<"$TASKS_RAW"

if [ "${#BACKENDS[@]}" -eq 0 ] || [ "${#TASKS[@]}" -eq 0 ]; then
  echo "ENDURANCE_BACKENDS and ENDURANCE_TASKS must be non-empty" >&2
  exit 1
fi

report_dir="$(dirname "$REPORT_PATH")"
mkdir -p "$report_dir"

{
  echo "# sidewhale endurance report"
  echo "# generated_at_utc	$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# backends	$BACKENDS_RAW"
  echo "# tasks	$TASKS_RAW"
  echo "# iterations	$ITERATIONS"
  echo "timestamp_utc	backend	task	iteration	status	duration_s"
} >"$REPORT_PATH"

tmp_log="$(mktemp -t sidewhale-endurance.XXXXXX.log)"
trap 'rm -f "$tmp_log"' EXIT

run_one() {
  local backend="$1"
  local task="$2"

  if [ "$backend" = "proot" ]; then
    make integration-test-upstream \
      UPSTREAM_TC_TASK="$task" \
      UPSTREAM_TC_TEST_ARGS=""
    return
  fi

  if [ "$backend" = "k8s" ]; then
    make integration-test-upstream-k8s \
      K8S_CONTEXT="${K8S_CONTEXT:-k3d-sidewhale-k8s}" \
      K8S_NAMESPACE="${K8S_NAMESPACE:-sidewhale-system}" \
      K8S_UPSTREAM_TASK="$task" \
      K8S_UPSTREAM_TEST_ARGS=""
    return
  fi

  echo "unsupported backend: $backend" >&2
  return 2
}

prewarm_k8s_images() {
  local images_raw="$1"
  local cluster_name="$2"
  [ -n "$images_raw" ] || return 0

  IFS=',' read -r -a images <<<"$images_raw"
  for image in "${images[@]}"; do
    image="$(echo "$image" | xargs)"
    [ -n "$image" ] || continue

    echo "Prewarming k8s image: $image"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
      docker pull "$image"
    fi
    k3d image import "$image" -c "$cluster_name"
  done
}

k8s_reset_done=false
k8s_image_prepared=false
k8s_images_prewarmed=false
for backend in "${BACKENDS[@]}"; do
  backend="$(echo "$backend" | xargs)"
  [ -n "$backend" ] || continue

  if [ "$backend" = "k8s" ] && [ "$k8s_image_prepared" = "false" ]; then
    if [ "$K8S_BUILD_IMAGE" = "true" ]; then
      echo "Building and importing Sidewhale image for k8s..."
      make integration-test-upstream-k8s-sidewhale-image \
        K8S_SIDEWHALE_IMAGE="${K8S_SIDEWHALE_IMAGE:-sidewhale:dev}" \
        K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-sidewhale-k8s}"
    fi
    k8s_image_prepared=true
  fi

  if [ "$backend" = "k8s" ] && [ "$k8s_reset_done" = "false" ]; then
    if [ "$K8S_RESET" = "true" ]; then
      echo "Resetting k8s baseline (mode=$K8S_RESET_MODE)..."
      make integration-test-upstream-k8s-reset \
        K8S_CONTEXT="${K8S_CONTEXT:-k3d-sidewhale-k8s}" \
        K8S_NAMESPACE="${K8S_NAMESPACE:-sidewhale-system}" \
        K8S_CLUSTER_NAME="${K8S_CLUSTER_NAME:-sidewhale-k8s}" \
        K8S_SIDEWHALE_IMAGE="${K8S_SIDEWHALE_IMAGE:-sidewhale:dev}" \
        K8S_RESET_MODE="$K8S_RESET_MODE"
    fi
    k8s_reset_done=true
  fi

  if [ "$backend" = "k8s" ] && [ "$k8s_images_prewarmed" = "false" ]; then
    prewarm_k8s_images "$K8S_PREPULL_IMAGES_RAW" "${K8S_CLUSTER_NAME:-sidewhale-k8s}"
    k8s_images_prewarmed=true
  fi

  for task in "${TASKS[@]}"; do
    task="$(echo "$task" | xargs)"
    [ -n "$task" ] || continue

    i=1
    while [ "$i" -le "$ITERATIONS" ]; do
      started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
      started_epoch="$(date +%s)"

      set +e
      run_one "$backend" "$task" >"$tmp_log" 2>&1
      rc=$?
      set -e

      ended_epoch="$(date +%s)"
      duration_s=$((ended_epoch - started_epoch))

      status="PASS"
      if [ "$rc" -ne 0 ]; then
        status="FAIL"
      fi

      printf "%s\t%s\t%s\t%d\t%s\t%d\n" \
        "$started_utc" "$backend" "$task" "$i" "$status" "$duration_s" >>"$REPORT_PATH"

      echo "[$started_utc] backend=$backend task=$task iteration=$i status=$status duration_s=$duration_s"

      i=$((i + 1))
    done
  done
done

echo
echo "Report written to $REPORT_PATH"
echo "Summary:"
awk -F '\t' '
  NR > 6 { key=$2 FS $3 FS $5; counts[key]++ }
  END {
    for (k in counts) {
      split(k, a, FS)
      printf "  backend=%s task=%s status=%s count=%d\n", a[1], a[2], a[3], counts[k]
    }
  }
' "$REPORT_PATH" | sort
