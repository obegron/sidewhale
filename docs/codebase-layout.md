# Codebase Layout

This document maps primary responsibilities to files so new features land in predictable places.

## API Surface

- `routes.go`: HTTP route wiring and endpoint dispatch.
- `handlers_container_named.go`: route-facing container handler names (clear intent wrappers).
- `handlers_container_lifecycle.go`: create/start/stop/kill/delete behavior.
- `handlers_container_observe.go`: inspect/top/events/logs/stats/wait behavior.
- `handlers_exec.go`, `handlers_image.go`, `handlers_network.go`, `handlers_archive.go`, `handlers_prune.go`: non-container endpoint handlers.

## Runtime Behavior

- `container_runtime_compat.go`: image/runtime compatibility rewrites (redis, nginx, sshd, tini, lldap).
- `container_runtime_state.go`: shared container state helpers used by handlers.
- `runtime_helpers.go`: process command/proot command construction and runtime guards.
- `command_resolution.go`: command path/shebang resolution inside rootfs.
- `process_monitor.go`: runtime process monitoring and termination behavior.

## Kubernetes Backend

- `k8s_runtime_client.go`: low-level Kubernetes API client and Pod create/exec/log/delete operations.
- `k8s_container_state.go`: Pod monitor loop and sync from Pod state to container state.
- `k8s_reconcile.go`: startup reconciliation and orphan cleanup.

## Storage and Model

- `types.go`: core models and API request/response structs.
- `store.go`: container state persistence and lifecycle storage primitives.
- `store_network.go`: network model persistence and container-network relationships.

## Image and Policy

- `image_pull.go`: image pull/extract pipeline and mirror fallback behavior.
- `image_extract.go`: layer extraction and filesystem safety.
- `image_policy.go`: allowlist/mirror policy parsing and matching.
- `image_store_helpers.go`: local image metadata/index helpers.
- `container_image_matchers.go`: image classification helpers and socket bind helpers.

## Container Identity and Env

- `container_env_helpers.go`: env merge/dedupe helpers.
- `container_identity_helpers.go`: hostname/hosts file writing and host alias shaping.
- `identity.go`: synthetic passwd/group handling for user mapping in rootfs.

## Utility

- `util_fs.go`: filesystem/path safety, copy helpers, generic JSON/error response helpers.
- `network_proxy.go`: port binding and TCP proxy implementation.
- `runtime_backend.go`: runtime backend normalization.
- `config.go`: flags and runtime config assembly.

## Test Organization

- `*_test.go` files are currently feature-grouped by domain (runtime, image, archive, endpoints).
- When adding new logic to a domain file, add/extend tests in the closest existing domain test file first.

## Placement Rule For New Features

- Add low-level mechanics to domain helper files.
- Keep handler files focused on HTTP request/response orchestration.
- Keep `routes.go` as routing-only.
- For Kubernetes backend additions, keep API transport in `k8s_runtime_client.go` and state translation in `k8s_container_state.go`.

## Kafka On K8s Backend (Planned)

For upcoming Kafka stabilization on `k8s` backend:

- Pod-spec level tuning belongs in `k8s_runtime_client.go` (command/env/resources/hostAliases/probes).
- Runtime state and readiness transitions belong in `k8s_container_state.go`.
- Image-specific compatibility shims should go to `container_runtime_compat.go` only when needed for host backend parity.
