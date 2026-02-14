FROM eclipse-temurin:17-jdk-jammy

ARG UPSTREAM_TC_REPO=https://github.com/testcontainers/testcontainers-java.git
ARG UPSTREAM_TC_REF=

RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    git \
    unzip \
  && rm -rf /var/lib/apt/lists/*

# Bundle upstream source so the in-cluster job can run without egress.
RUN git clone --depth=1 "$UPSTREAM_TC_REPO" /opt/testcontainers-java \
  && if [ -n "$UPSTREAM_TC_REF" ]; then \
       git -C /opt/testcontainers-java fetch --depth=1 origin "$UPSTREAM_TC_REF" \
       && git -C /opt/testcontainers-java checkout --force FETCH_HEAD; \
     fi

WORKDIR /workspace

COPY run-upstream.sh /usr/local/bin/run-upstream.sh

ENTRYPOINT ["/usr/local/bin/run-upstream.sh"]
