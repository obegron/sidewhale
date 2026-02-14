# Deployment Profiles

Sidewhale supports two deployment profiles with one API surface.

## 1) Sidecar + Host Backend

- Runtime backend: `host`
- Placement: same Pod as your test runner
- Docker endpoint: usually `unix:///var/run/docker.sock`
- Permissions: minimal, no Kubernetes RBAC required

Use when:

- you want lowest privilege and simple setup
- your test modules fit host-backend compatibility constraints

Manifest:

- `deploy/sidewhale-host-sidecar.yaml`

## 2) Shared Service + K8s Backend

- Runtime backend: `k8s`
- Placement: standalone Deployment (for example in `sidewhale-system`)
- Docker endpoint: `tcp://sidewhale.sidewhale-system.svc.cluster.local:23750`
- Permissions: ServiceAccount + RBAC to create/manage worker Pods
- State: persistent volume is recommended (the provided manifest uses a PVC `sidewhale-state`)
- Optional: set `--k8s-runtime-namespace=<ns>` to place worker Pods in a different namespace
- Optional: set `--k8s-image-pull-secrets=<secret1,secret2>` for private image pulls
- Optional: set `--k8s-cleanup-orphans=false` to disable orphan worker-pod deletion during startup reconcile

Use when:

- you need real Kubernetes container networking semantics
- you want to avoid `proot` runtime limitations
- you want centralized policy/mirror control

Manifest:

- `deploy/sidewhale-k8s-runtime.yaml`

Local development access (optional):

- Apply `deploy/sidewhale-k8s-runtime-nodeport.yaml`
- For k3d, publish the NodePort at cluster create time (example: `k3d cluster create sidewhale-k8s --servers 1 --agents 1 -p "32375:32375@loadbalancer"`).
- Then use `DOCKER_HOST=tcp://127.0.0.1:32375`.
- If you did not publish the port at cluster create time, use `kubectl port-forward -n sidewhale-system svc/sidewhale 23750:23750` instead.

## Notes

- `k8s` backend start path is currently scaffolded in code but not wired end-to-end yet.
- `host` backend is the current production path.
