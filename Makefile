SHELL := /bin/bash

BINARY := sidewhale
IMAGE_NAME ?= sidewhale
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PLATFORM ?= linux/amd64
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X 'main.version=$(VERSION)' -X 'main.gitCommit=$(GIT_COMMIT)' -X 'main.buildTime=$(BUILD_TIME)'

.PHONY: help build image docker-build docker-push image-run smoke-pull integration-test integration-test-upstream integration-test-upstream-mirrored integration-test-upstream-k8s-image integration-test-upstream-k8s integration-test-upstream-k8s-logs integration-test-upstream-k8s-clean integration-test-kafka-listener-k8s integration-test-kafka-listener-k8s-clean integration-test-kafka-log-stream-k8s integration-test-kafka-log-stream-k8s-clean integration-test-kafka-upstream-shape-k8s integration-test-kafka-upstream-shape-k8s-clean clean

help:
	@echo "Targets:"
	@echo "  build   Build $(BINARY) binary"
	@echo "  image         Build container image ($(IMAGE_NAME):$(VERSION))"
	@echo "  docker-build  Build image via buildx for $(PLATFORM)"
	@echo "  docker-push   Build and push image with provenance + SBOM"
	@echo "  image-run   Run image in host network mode and print DOCKER_HOST env var"
	@echo "  smoke-pull  Quick API smoke test (ping/version + image pull)"
	@echo "  integration-test Run Java Testcontainers smoke tests against Sidewhale"
	@echo "  integration-test-upstream Run selected upstream non-turbo testcontainers-java tests"
	@echo "  integration-test-upstream-mirrored Run upstream tests through local registry mirrors"
	@echo "  integration-test-upstream-k8s-image Build upstream Gradle runner image"
	@echo "  integration-test-upstream-k8s Run upstream tests in a Kubernetes Job"
	@echo "  integration-test-upstream-k8s-logs Stream logs from the Kubernetes Job"
	@echo "  integration-test-upstream-k8s-clean Delete the Kubernetes Job"
	@echo "  integration-test-kafka-listener-k8s Run Kafka listener smoke test in-cluster against Sidewhale"
	@echo "  integration-test-kafka-listener-k8s-clean Delete Kafka listener smoke test Job"
	@echo "  integration-test-kafka-log-stream-k8s Run Kafka log-stream smoke test in-cluster against Sidewhale"
	@echo "  integration-test-kafka-log-stream-k8s-clean Delete Kafka log-stream smoke test Job"
	@echo "  integration-test-kafka-upstream-shape-k8s Run Kafka smoke test with Testcontainers upstream startup shape"
	@echo "  integration-test-kafka-upstream-shape-k8s-clean Delete Kafka upstream-shape smoke test Job"
	@echo "  clean   Remove build artifacts"
	@echo "Variables:"
	@echo "  VERSION    Override version tag (default: git describe or dev)"
	@echo "  IMAGE_NAME Override image name (default: sidewhale)"
	@echo "  PLATFORM   buildx platform (default: linux/amd64)"
	@echo "  SMOKE_IMAGE Image used by smoke-pull (default: redis:7-alpine)"
	@echo "  SIDEWHALE_RUN_ARGS Extra args passed to sidewhale in smoke-pull"
	@echo "  UPSTREAM_TC_TASK Gradle task for integration-test-upstream"
	@echo "  UPSTREAM_TC_TEST_ARGS Extra --tests filters for integration-test-upstream"
	@echo "  UPSTREAM_TC_LOCAL_MAP Space-separated src=dst mirror seed mappings"
	@echo "  K8S_CONTEXT Kubernetes context for in-cluster runner"
	@echo "  K8S_NAMESPACE Kubernetes namespace for in-cluster runner"
	@echo "  K8S_UPSTREAM_REPO Upstream repository URL baked into runner image"
	@echo "  K8S_UPSTREAM_REF Optional branch/tag/SHA baked into runner image"
	@echo "  K8S_UPSTREAM_TASK Gradle task for in-cluster runner"
	@echo "  K8S_UPSTREAM_TEST_ARGS Test args for in-cluster runner"
	@echo "  K8S_UPSTREAM_PRECOMPILE_TASKS Gradle tasks precompiled in runner image"
	@echo "  K8S_UPSTREAM_PREWARM_DEPS Resolve runner deps at image build for offline runs"

build:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) .

image:
	docker build --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(IMAGE_NAME):$(VERSION) .

docker-build:
	docker buildx build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --load

docker-push:
	docker buildx build --platform $(PLATFORM) --provenance=true --sbom=true --build-arg VERSION=$(VERSION) --build-arg GIT_COMMIT=$(GIT_COMMIT) --build-arg BUILD_TIME=$(BUILD_TIME) -t $(IMAGE_NAME):$(VERSION) -t $(IMAGE_NAME):latest . --push

image-run:
	@echo "Set:"
	@echo "  export DOCKER_HOST=tcp://127.0.0.1:23750"
	@echo ""
	docker run --rm --network host $(IMAGE_NAME):$(VERSION) --listen :23750 --listen-unix /tmp/sidewhale/docker.sock

SMOKE_IMAGE ?= redis:7-alpine
SIDEWHALE_RUN_ARGS ?=
IT_SMOKE_DIR ?= it/testcontainers-smoke
UPSTREAM_TC_DIR ?= /tmp/testcontainers-java
UPSTREAM_TC_REPO ?= https://github.com/testcontainers/testcontainers-java.git
UPSTREAM_TC_TASK ?= :testcontainers-postgresql:test
UPSTREAM_TC_TEST_ARGS ?= --tests "org.testcontainers.postgresql.CompatibleImageTest"
UPSTREAM_TC_MIRROR_REGISTRY ?= 127.0.0.1:5001
UPSTREAM_TC_MIRROR_CONTAINER ?= sidewhale-registry-cache
UPSTREAM_TC_MIRROR_STATE_DIR ?= /tmp/sidewhale-registry
UPSTREAM_TC_MIRROR_IMAGES ?= postgres:9.6.12 pgvector/pgvector:pg16 postgis/postgis:16-3.4-alpine timescale/timescaledb:2.14.2-pg16
UPSTREAM_TC_MIRROR_PROXY_REMOTE ?= https://registry-1.docker.io
UPSTREAM_TC_LOCAL_MAP ?= docker.io/testcontainers/ryuk@sha256:bcbee39cd601396958ba1bd06ea14ad64ce0ea709de29a427d741d1f5262080a=$(UPSTREAM_TC_MIRROR_REGISTRY)/testcontainers/ryuk:0.7.0 alpine@sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d=$(UPSTREAM_TC_MIRROR_REGISTRY)/library/alpine:3.17
UPSTREAM_TC_DIGEST_MIRRORS ?= docker.io/testcontainers/ryuk@sha256:bcbee39cd601396958ba1bd06ea14ad64ce0ea709de29a427d741d1f5262080a=$(UPSTREAM_TC_MIRROR_REGISTRY)/testcontainers/ryuk:0.7.0,alpine@sha256:1775bebec23e1f3ce486989bfc9ff3c4e951690df84aa9f926497d82f2ffca9d=$(UPSTREAM_TC_MIRROR_REGISTRY)/library/alpine:3.17
K8S_CONTEXT ?= k3d-sidewhale-k8s
K8S_CLUSTER_NAME ?= sidewhale-k8s
K8S_NAMESPACE ?= sidewhale-system
K8S_UPSTREAM_JOB_NAME ?= sidewhale-upstream-tests
K8S_UPSTREAM_JOB_TIMEOUT ?= 1800s
K8S_UPSTREAM_RUNNER_IMAGE ?= sidewhale-test-runner
K8S_UPSTREAM_RUNNER_TAG ?= dev
K8S_UPSTREAM_REPO ?= https://github.com/testcontainers/testcontainers-java.git
K8S_UPSTREAM_REF ?=
K8S_UPSTREAM_TASK ?= :testcontainers:test
K8S_UPSTREAM_TEST_ARGS ?= --tests org.testcontainers.containers.ContainerStateTest
K8S_UPSTREAM_EXTRA_GRADLE_ARGS ?= --rerun-tasks --max-workers=1 --no-daemon
K8S_SIDEWHALE_DOCKER_HOST ?=
K8S_UPSTREAM_PRECOMPILE_TASKS ?= :testcontainers:testClasses :testcontainers-postgresql:testClasses :testcontainers-ldap:testClasses :testcontainers-mockserver:testClasses
K8S_UPSTREAM_PREWARM_DEPS ?= true
K8S_KAFKA_IT_JOB_NAME ?= sidewhale-kafka-listener-it
K8S_KAFKA_IT_TIMEOUT ?= 600s
K8S_KAFKA_LOG_IT_JOB_NAME ?= sidewhale-kafka-log-it
K8S_KAFKA_LOG_IT_TIMEOUT ?= 600s
K8S_KAFKA_UPSTREAM_IT_JOB_NAME ?= sidewhale-kafka-upstream-shape-it
K8S_KAFKA_UPSTREAM_IT_TIMEOUT ?= 900s

smoke-pull:
	@set -euo pipefail; \
	container=sidewhale-smoke; \
	docker rm -f $$container >/dev/null 2>&1 || true; \
	trap 'docker rm -f $$container >/dev/null 2>&1 || true' EXIT; \
	docker run -d --name $$container --network host $(IMAGE_NAME):$(VERSION) --listen :23750 --listen-unix /tmp/sidewhale/docker.sock $(SIDEWHALE_RUN_ARGS) >/dev/null; \
	sleep 1; \
	curl -fsS http://127.0.0.1:23750/_ping >/dev/null; \
	curl -fsS http://127.0.0.1:23750/version >/dev/null; \
	curl -fsS -X POST "http://127.0.0.1:23750/v1.41/images/create?fromImage=$(SMOKE_IMAGE)" >/dev/null; \
	echo "smoke ok: pulled $(SMOKE_IMAGE)"

integration-test:
	@set -euo pipefail; \
	export DOCKER_HOST="$${DOCKER_HOST:-tcp://127.0.0.1:23750}"; \
	export TESTCONTAINERS_RYUK_DISABLED="$${TESTCONTAINERS_RYUK_DISABLED:-true}"; \
	if ! curl -fsS "$${DOCKER_HOST/tcp:\/\//http:\/\/}/version" >/dev/null; then \
		echo "sidewhale not reachable at $$DOCKER_HOST (start sidewhale first)"; \
		exit 1; \
	fi; \
	cd "$(IT_SMOKE_DIR)"; \
	mvn -q test

integration-test-upstream:
	@set -euo pipefail; \
	if [ ! -d "$(UPSTREAM_TC_DIR)/.git" ]; then \
		git clone "$(UPSTREAM_TC_REPO)" "$(UPSTREAM_TC_DIR)"; \
	else \
		git -C "$(UPSTREAM_TC_DIR)" fetch --depth=1 origin; \
		git -C "$(UPSTREAM_TC_DIR)" reset --hard origin/HEAD; \
	fi; \
	export DOCKER_HOST="$${DOCKER_HOST:-tcp://127.0.0.1:23750}"; \
	export TESTCONTAINERS_RYUK_DISABLED="$${TESTCONTAINERS_RYUK_DISABLED:-true}"; \
	export TESTCONTAINERS_CHECKS_DISABLE="$${TESTCONTAINERS_CHECKS_DISABLE:-true}"; \
	export GRADLE_USER_HOME="$${GRADLE_USER_HOME:-/tmp/.gradle-sidewhale}"; \
	if ! curl -fsS "$${DOCKER_HOST/tcp:\/\//http:\/\/}/version" >/dev/null; then \
		echo "sidewhale not reachable at $$DOCKER_HOST (start sidewhale first)"; \
		exit 1; \
	fi; \
	cd "$(UPSTREAM_TC_DIR)"; \
	./gradlew $(UPSTREAM_TC_TASK) \
		$(UPSTREAM_TC_TEST_ARGS) \
		--no-daemon

integration-test-upstream-mirrored:
	@set -euo pipefail; \
	registry_addr="$(UPSTREAM_TC_MIRROR_REGISTRY)"; \
	registry_container="$(UPSTREAM_TC_MIRROR_CONTAINER)"; \
	registry_state_dir="$(UPSTREAM_TC_MIRROR_STATE_DIR)"; \
	sidewhale_container="sidewhale-upstream-mirror"; \
	docker rm -f "$$registry_container" >/dev/null 2>&1 || true; \
	mkdir -p "$$registry_state_dir"; \
	docker run -d --name "$$registry_container" --network host \
		-e REGISTRY_STORAGE_DELETE_ENABLED=true \
		-e REGISTRY_PROXY_REMOTEURL="$(UPSTREAM_TC_MIRROR_PROXY_REMOTE)" \
		-v "$$registry_state_dir:/var/lib/registry" \
		registry:2 >/dev/null; \
	trap 'docker rm -f "$$sidewhale_container" >/dev/null 2>&1 || true' EXIT; \
	for pair in $(UPSTREAM_TC_LOCAL_MAP); do \
		src="$${pair%%=*}"; \
		dst="$${pair#*=}"; \
		if ! docker image inspect "$$src" >/dev/null 2>&1; then \
			echo "local seed source missing: $$src"; \
			continue; \
		fi; \
		if docker image inspect "$$dst" >/dev/null 2>&1; then \
			echo "local seed hit: $$src -> $$dst"; \
			continue; \
		fi; \
		echo "local seed: $$src -> $$dst"; \
		docker tag "$$src" "$$dst"; \
		docker push "$$dst" >/dev/null; \
	done; \
	for img in $(UPSTREAM_TC_MIRROR_IMAGES); do \
		mirror_img="$$img"; \
		mirror_img="$${mirror_img#docker.io/}"; \
		mirror_img="$${mirror_img#index.docker.io/}"; \
		repo_part="$$img"; \
		repo_part="$${repo_part%%@*}"; \
		repo_part="$${repo_part%%:*}"; \
		if [[ "$$repo_part" != */* ]]; then \
			mirror_img="library/$$img"; \
		fi; \
		if docker image inspect "$$registry_addr/$$mirror_img" >/dev/null 2>&1; then \
			echo "mirror cache hit: $$img"; \
			continue; \
		fi; \
		echo "mirror cache miss: $$img"; \
		docker pull "$$registry_addr/$$mirror_img" >/dev/null; \
	done; \
	docker rm -f "$$sidewhale_container" >/dev/null 2>&1 || true; \
	docker run -d --name "$$sidewhale_container" --network host \
		sidewhale:dev \
		--listen :23750 \
		--listen-unix /tmp/sidewhale/docker.sock \
		--image-mirrors "$(UPSTREAM_TC_DIGEST_MIRRORS),docker.io/=$$registry_addr/,index.docker.io/=$$registry_addr/" >/dev/null; \
	$(MAKE) integration-test-upstream

integration-test-upstream-k8s-image:
	docker build \
		--build-arg UPSTREAM_TC_REPO=$(K8S_UPSTREAM_REPO) \
		--build-arg UPSTREAM_TC_REF=$(K8S_UPSTREAM_REF) \
		--build-arg PRECOMPILE_TASKS="$(K8S_UPSTREAM_PRECOMPILE_TASKS)" \
		--build-arg PREWARM_DEPS=$(K8S_UPSTREAM_PREWARM_DEPS) \
		-t $(K8S_UPSTREAM_RUNNER_IMAGE):$(K8S_UPSTREAM_RUNNER_TAG) \
		-f it/upstream-runner/Dockerfile it/upstream-runner
	k3d image import $(K8S_UPSTREAM_RUNNER_IMAGE):$(K8S_UPSTREAM_RUNNER_TAG) -c $(K8S_CLUSTER_NAME)

integration-test-upstream-k8s:
	@set -euo pipefail; \
	$(MAKE) integration-test-upstream-k8s-image; \
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) get svc sidewhale >/dev/null; \
	sidewhale_host="$(K8S_SIDEWHALE_DOCKER_HOST)"; \
	if [ -z "$$sidewhale_host" ]; then \
		endpoint_ip="$$(kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) get endpoints sidewhale -o jsonpath='{.subsets[0].addresses[0].ip}')"; \
		if [ -z "$$endpoint_ip" ]; then \
			echo "failed to resolve sidewhale endpoint IP"; \
			exit 1; \
		fi; \
		sidewhale_host="tcp://$$endpoint_ip:23750"; \
	fi; \
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) delete job $(K8S_UPSTREAM_JOB_NAME) --ignore-not-found >/dev/null; \
	K8S_UPSTREAM_JOB_NAME="$(K8S_UPSTREAM_JOB_NAME)" \
	K8S_NAMESPACE="$(K8S_NAMESPACE)" \
	K8S_UPSTREAM_RUNNER_IMAGE="$(K8S_UPSTREAM_RUNNER_IMAGE)" \
	K8S_UPSTREAM_RUNNER_TAG="$(K8S_UPSTREAM_RUNNER_TAG)" \
	K8S_SIDEWHALE_DOCKER_HOST="$$sidewhale_host" \
	K8S_UPSTREAM_TASK="$(K8S_UPSTREAM_TASK)" \
	K8S_UPSTREAM_TEST_ARGS="$(K8S_UPSTREAM_TEST_ARGS)" \
	K8S_UPSTREAM_EXTRA_GRADLE_ARGS="$(K8S_UPSTREAM_EXTRA_GRADLE_ARGS)" \
	./it/upstream-runner/generate-job.sh | kubectl --context $(K8S_CONTEXT) apply -f -
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) wait --for=condition=complete job/$(K8S_UPSTREAM_JOB_NAME) --timeout=$(K8S_UPSTREAM_JOB_TIMEOUT)
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) logs -f job/$(K8S_UPSTREAM_JOB_NAME)

integration-test-upstream-k8s-logs:
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) logs -f job/$(K8S_UPSTREAM_JOB_NAME)

integration-test-upstream-k8s-clean:
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) delete job $(K8S_UPSTREAM_JOB_NAME) --ignore-not-found

integration-test-kafka-listener-k8s:
	K8S_CONTEXT="$(K8S_CONTEXT)" \
	K8S_NAMESPACE="$(K8S_NAMESPACE)" \
	K8S_KAFKA_IT_JOB_NAME="$(K8S_KAFKA_IT_JOB_NAME)" \
	K8S_KAFKA_IT_TIMEOUT="$(K8S_KAFKA_IT_TIMEOUT)" \
	K8S_SIDEWHALE_DOCKER_HOST="$(K8S_SIDEWHALE_DOCKER_HOST)" \
	./it/kafka-listener-smoke/run.sh

integration-test-kafka-listener-k8s-clean:
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) delete job $(K8S_KAFKA_IT_JOB_NAME) --ignore-not-found

integration-test-kafka-log-stream-k8s:
	K8S_CONTEXT="$(K8S_CONTEXT)" \
	K8S_NAMESPACE="$(K8S_NAMESPACE)" \
	K8S_KAFKA_LOG_IT_JOB_NAME="$(K8S_KAFKA_LOG_IT_JOB_NAME)" \
	K8S_KAFKA_LOG_IT_TIMEOUT="$(K8S_KAFKA_LOG_IT_TIMEOUT)" \
	K8S_SIDEWHALE_DOCKER_HOST="$(K8S_SIDEWHALE_DOCKER_HOST)" \
	./it/kafka-log-stream-smoke/run.sh

integration-test-kafka-log-stream-k8s-clean:
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) delete job $(K8S_KAFKA_LOG_IT_JOB_NAME) --ignore-not-found

integration-test-kafka-upstream-shape-k8s:
	K8S_CONTEXT="$(K8S_CONTEXT)" \
	K8S_NAMESPACE="$(K8S_NAMESPACE)" \
	K8S_KAFKA_UPSTREAM_IT_JOB_NAME="$(K8S_KAFKA_UPSTREAM_IT_JOB_NAME)" \
	K8S_KAFKA_UPSTREAM_IT_TIMEOUT="$(K8S_KAFKA_UPSTREAM_IT_TIMEOUT)" \
	K8S_SIDEWHALE_DOCKER_HOST="$(K8S_SIDEWHALE_DOCKER_HOST)" \
	./it/kafka-upstream-shape-smoke/run.sh

integration-test-kafka-upstream-shape-k8s-clean:
	kubectl --context $(K8S_CONTEXT) -n $(K8S_NAMESPACE) delete job $(K8S_KAFKA_UPSTREAM_IT_JOB_NAME) --ignore-not-found

clean:
	rm -f $(BINARY)
