# Sidewhale Compatibility Matrix (Host Backend)

Last updated: 2026-02-22

This matrix reflects what we validated in the current upstream test loop (`testcontainers-java` + Sidewhale host backend with `proot`).

Status legend:

- `Confirmed`: validated in our recent runs
- `Partial`: works for some cases; known gaps remain
- `Unsupported`: outside current host-backend scope

## Docker API / Behavior

| Area | Status | Notes |
|---|---|---|
| Container lifecycle (`create/start/stop/delete/inspect`) | Confirmed | Core Testcontainers path is stable. |
| Image pull (`/images/create`) | Confirmed | Streaming progress implemented; digest/local mirror flows exercised. |
| Logs (`/containers/{id}/logs`) | Confirmed | Non-stream and follow flows used in upstream tests. |
| Wait/state (`/containers/{id}/wait`, running status) | Confirmed | Wait/error-state behavior exercised in core tests. |
| File/archive copy (`/containers/{id}/archive` HEAD/GET/PUT) | Confirmed | Core file-operation coverage now stable, including copy-back from stopped containers and large-file copy paths in upstream tests. |
| Port publishing | Confirmed | Host TCP proxy mapping used broadly across modules. |
| Listener/bind address compatibility | Partial | Strongly improved for single-container services (Kafka listener flow now passing), but image-specific bind assumptions can still require compatibility handling. |
| Networks API surface | Partial | Basic endpoints exist, but no real Docker network namespace semantics. |
| Cross-container DNS/service discovery | Unsupported | No embedded DNS; name-based cluster discovery is a known gap. |

## Testcontainers Java Modules

| Module / Test Area | Status | Notes |
|---|---|---|
| Core (`DockerClientFactoryTest`, `ContainerStateTest`, `ImagePullTest`, logs/wait-focused tests) | Confirmed | Core correctness loop repeatedly exercised. |
| PostgreSQL | Confirmed | Project acceptance target; repeatedly validated. |
| Redis (module + smoke variants) | Confirmed | Single-container and repeated smoke runs validated. |
| MySQL | Confirmed | Module tests executed successfully in host mode. |
| MariaDB | Confirmed | Module tests executed successfully in host mode. |
| MSSQL Server | Confirmed | Module tests executed successfully; marked useful target runtime. |
| Vault | Confirmed | Passed after mirroring required images. |
| Solr | Confirmed | Module tests executed successfully in recent loop. |
| JUnit Jupiter integration tests (selected) | Confirmed | Selected inheritance/restart tests validated. |
| MockServer | Confirmed | `:testcontainers-mockserver:test` passed in k8s upstream loop (`MockServerContainerTest`: standard, TLS, mTLS, and wait-strategy paths). |
| Nginx module | Partial | Works only with Sidewhale nginx compat handling; privileged-port behavior is image-sensitive. |
| LDAP (LLDAP) | Confirmed | `:testcontainers-ldap:test` passed in k8s upstream loop (`LLdapContainerTest`: default bind, URL-based bind, custom base DN, custom password). |
| Kafka (single container) | Partial | Listener-based single-node flow (`KafkaContainerTest.testUsageWithListener`) now passes in k8s backend. Broader Kafka matrix still in progress. |
| Kafka cluster examples | Unsupported | Requires container-to-container name resolution/network behavior not provided by host backend. |
| Cassandra | Partial | `:testcontainers-cassandra:test` runs many tests successfully, but startup/readiness remains flaky in host mode. Recent failures include `Timed out waiting for Cassandra to be accessible for query execution` and `NoHostAvailableException`/closed channel in `testConfigurationOverride`. |
| Oracle Free | Supported (K8s) | Full support on K8s backend with automated memory (4Gi) and startup probe (healthcheck.sh) injection. Still unsupported on host backend due to `proot` syscall constraints. |
| DB2 | Unsupported | Startup/instance setup constraints not satisfied under current runtime model. |
| Compose-based tests | Unsupported | Compose/network feature set is intentionally out of scope. |
| ImageFromDockerfile/build flows | Unsupported | Build API not in MVP scope. |

## Practical Guidance

Best fit today:

- single-container dependency services used by application tests
- JDBC/Redis-like modules that only need lifecycle, ports, logs, and inspect
- mirrored-image environments where external pull pressure is controlled

Known non-fit today:

- distributed cluster tests that depend on Docker DNS/network semantics
- modules/images requiring privileged internal bind behavior without adaptation
- heavy runtime/kernel-sensitive images (for example Oracle/DB2 class)

## Scope Statement

Current Sidewhale target is:

- **High correctness for host-backend Testcontainers essentials**
- **Not** full Docker runtime/network parity

If networking parity becomes a hard requirement, treat it as a separate major milestone rather than incremental tweaks.
