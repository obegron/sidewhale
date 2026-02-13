package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCommandInRootfs(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "app"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "app", "ryuk"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	got := resolveCommandInRootfs(rootfs, nil, []string{"/bin/ryuk"})
	if len(got) != 1 || got[0] != "/app/ryuk" {
		t.Fatalf("resolveCommandInRootfs returned %v, want [/app/ryuk]", got)
	}
}

func TestResolveCommandInRootfsRewritesEnvShebang(t *testing.T) {
	rootfs := t.TempDir()
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "local", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir script dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "usr", "bin"), 0o755); err != nil {
		t.Fatalf("mkdir usr/bin: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "bin"), 0o755); err != nil {
		t.Fatalf("mkdir bin: %v", err)
	}
	if err := os.Symlink("/bin/busybox", filepath.Join(rootfs, "usr", "bin", "env")); err != nil {
		t.Fatalf("symlink env: %v", err)
	}
	if err := os.WriteFile(filepath.Join(rootfs, "bin", "bash"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write bash: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(rootfs, "usr", "local", "bin", "docker-entrypoint.sh"),
		[]byte("#!/usr/bin/env bash\nset -e\n"),
		0o755,
	); err != nil {
		t.Fatalf("write entrypoint: %v", err)
	}

	got := resolveCommandInRootfs(rootfs, nil, []string{"/usr/local/bin/docker-entrypoint.sh", "postgres"})
	want := []string{"/bin/bash", "/usr/local/bin/docker-entrypoint.sh", "postgres"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("resolveCommandInRootfs returned %v, want %v", got, want)
	}
}

func TestRewriteKnownEntrypointCompatMSSQL(t *testing.T) {
	got := rewriteKnownEntrypointCompat([]string{"/bin/bash", "/opt/mssql/bin/launch_sqlservr.sh", "/opt/mssql/bin/sqlservr"})
	want := []string{"/opt/mssql/bin/sqlservr"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("rewriteKnownEntrypointCompat returned %v, want %v", got, want)
	}
}

func TestIsRyukImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{image: "testcontainers/ryuk:0.8.1", want: true},
		{image: "docker.io/testcontainers/ryuk:latest", want: true},
		{image: "postgres:16-alpine", want: false},
	}
	for _, tt := range tests {
		if got := isRyukImage(tt.image); got != tt.want {
			t.Fatalf("isRyukImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestDockerHostForInnerClients(t *testing.T) {
	tests := []struct {
		unixPath string
		host     string
		want     string
	}{
		{unixPath: "/tmp/sidewhale/docker.sock", host: "127.0.0.1:8080", want: "unix:///tmp/sidewhale/docker.sock"},
		{host: "127.0.0.1:8080", want: "tcp://127.0.0.1:8080"},
		{host: "", want: "tcp://127.0.0.1:23750"},
		{host: "tcp://10.0.0.5:2375", want: "tcp://10.0.0.5:2375"},
	}
	for _, tt := range tests {
		if got := dockerHostForInnerClients(tt.unixPath, tt.host); got != tt.want {
			t.Fatalf("dockerHostForInnerClients(%q,%q) = %q, want %q", tt.unixPath, tt.host, got, tt.want)
		}
	}
}

func TestDockerSocketBindsForContainer(t *testing.T) {
	rootfs := t.TempDir()
	c := &Container{Rootfs: rootfs}
	binds, err := dockerSocketBindsForContainer(c, "/tmp/sidewhale/docker.sock")
	if err != nil {
		t.Fatalf("dockerSocketBindsForContainer error: %v", err)
	}
	if len(binds) != 3 {
		t.Fatalf("bind count = %d, want 3", len(binds))
	}
	if binds[0] != "/tmp/sidewhale/docker.sock:/tmp/sidewhale/docker.sock" {
		t.Fatalf("unexpected bind[0]: %q", binds[0])
	}
	if binds[1] != "/tmp/sidewhale/docker.sock:/var/run/docker.sock" {
		t.Fatalf("unexpected bind[1]: %q", binds[1])
	}
	if binds[2] != "/tmp/sidewhale/docker.sock:/run/docker.sock" {
		t.Fatalf("unexpected bind[2]: %q", binds[2])
	}
}

func TestUnixSocketPathFromContainerEnv(t *testing.T) {
	env := []string{"A=B", "DOCKER_HOST=unix:///tmp/sidewhale/docker.sock"}
	if got := unixSocketPathFromContainerEnv(env); got != "/tmp/sidewhale/docker.sock" {
		t.Fatalf("unixSocketPathFromContainerEnv = %q, want %q", got, "/tmp/sidewhale/docker.sock")
	}
}

func TestIsConfluentKafkaImage(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{image: "confluentinc/cp-kafka:7.6.1", want: true},
		{image: "docker.io/confluentinc/cp-kafka:latest", want: true},
		{image: "apache/kafka:3", want: false},
	}
	for _, tt := range tests {
		if got := isConfluentKafkaImage(tt.image); got != tt.want {
			t.Fatalf("isConfluentKafkaImage(%q) = %v, want %v", tt.image, got, tt.want)
		}
	}
}

func TestEnsureEnvContainsToken(t *testing.T) {
	t.Run("adds key when missing", func(t *testing.T) {
		env := []string{"A=B"}
		got := ensureEnvContainsToken(env, "KAFKA_OPTS", "-Dzookeeper.admin.enableServer=false")
		if !envHasKey(got, "KAFKA_OPTS") {
			t.Fatalf("expected KAFKA_OPTS to be added")
		}
		if got[len(got)-1] != "KAFKA_OPTS=-Dzookeeper.admin.enableServer=false" {
			t.Fatalf("unexpected KAFKA_OPTS value: %q", got[len(got)-1])
		}
	})

	t.Run("appends token to existing value", func(t *testing.T) {
		env := []string{"KAFKA_OPTS=-Xmx256m"}
		got := ensureEnvContainsToken(env, "KAFKA_OPTS", "-Dzookeeper.admin.enableServer=false")
		if got[0] != "KAFKA_OPTS=-Xmx256m -Dzookeeper.admin.enableServer=false" {
			t.Fatalf("unexpected KAFKA_OPTS value: %q", got[0])
		}
	})

	t.Run("does not duplicate token", func(t *testing.T) {
		env := []string{"KAFKA_OPTS=-Xmx256m -Dzookeeper.admin.enableServer=false"}
		got := ensureEnvContainsToken(env, "KAFKA_OPTS", "-Dzookeeper.admin.enableServer=false")
		if got[0] != env[0] {
			t.Fatalf("expected value to stay unchanged, got %q", got[0])
		}
	})
}
