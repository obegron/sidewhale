package main

import "testing"

func TestApplyImageCompatAddsOracleHostname(t *testing.T) {
	env := applyImageCompat(nil, "db-host", "oracle/database:21", "oracle/database:21", "", "")
	if !envHasKey(env, "ORACLE_HOSTNAME") {
		t.Fatalf("expected ORACLE_HOSTNAME to be set")
	}
}

func TestApplyImageCompatSetsRyukDockerHost(t *testing.T) {
	env := applyImageCompat(nil, "tc", "testcontainers/ryuk:0.8.1", "testcontainers/ryuk:0.8.1", "/tmp/sidewhale/docker.sock", "127.0.0.1:23750")
	found := false
	for _, e := range env {
		if e == "DOCKER_HOST=unix:///tmp/sidewhale/docker.sock" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected DOCKER_HOST unix socket entry in env: %v", env)
	}
}

func TestApplyImageCompatKafkaTokenDedup(t *testing.T) {
	initial := []string{"KAFKA_OPTS=-Xmx256m -Dzookeeper.admin.enableServer=false"}
	env := applyImageCompat(initial, "kafka", "confluentinc/cp-kafka:7.6.1", "confluentinc/cp-kafka:7.6.1", "", "")
	val := ""
	for _, e := range env {
		if k, v := splitEnv(e); k == "KAFKA_OPTS" {
			val = v
			break
		}
	}
	if val == "" {
		t.Fatalf("expected KAFKA_OPTS in env")
	}
	if val != "-Xmx256m -Dzookeeper.admin.enableServer=false" {
		t.Fatalf("expected KAFKA_OPTS unchanged, got %q", val)
	}
}

func TestApplyImageCompatKafkaListenersRewrittenForBind(t *testing.T) {
	initial := []string{"KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,BROKER://localhost:9093,TC-0://kafka:19092"}
	env := applyImageCompat(initial, "kafka", "apache/kafka-native:3.8.0", "apache/kafka-native:3.8.0", "", "")
	val := ""
	for _, e := range env {
		if k, v := splitEnv(e); k == "KAFKA_LISTENERS" {
			val = v
			break
		}
	}
	if val == "" {
		t.Fatalf("expected KAFKA_LISTENERS in env")
	}
	expected := "PLAINTEXT://0.0.0.0:9092,BROKER://0.0.0.0:9093,TC-0://0.0.0.0:19092"
	if val != expected {
		t.Fatalf("expected rewritten listeners %q, got %q", expected, val)
	}
}

func TestApplyImageCompatAddsZookeeperJavaFlags(t *testing.T) {
	env := applyImageCompat(nil, "zk", "library/zookeeper:3.8.0", "library/zookeeper:3.8.0", "", "")
	jvmFlags := ""
	javaToolOptions := ""
	jmxDisable := ""
	for _, e := range env {
		k, v := splitEnv(e)
		if k == "JVMFLAGS" {
			jvmFlags = v
		}
		if k == "JAVA_TOOL_OPTIONS" {
			javaToolOptions = v
		}
		if k == "JMXDISABLE" {
			jmxDisable = v
		}
	}
	if jvmFlags == "" || javaToolOptions == "" || jmxDisable == "" {
		t.Fatalf("expected JVMFLAGS, JAVA_TOOL_OPTIONS, and JMXDISABLE, got %v", env)
	}
	if jvmFlags != "-XX:-UseContainerSupport" {
		t.Fatalf("expected JVMFLAGS token, got %q", jvmFlags)
	}
	if javaToolOptions != "-XX:-UseContainerSupport" {
		t.Fatalf("expected JAVA_TOOL_OPTIONS token, got %q", javaToolOptions)
	}
	if jmxDisable != "true" {
		t.Fatalf("expected JMXDISABLE=true, got %q", jmxDisable)
	}
}

func TestApplyImageCompatZookeeperTokenDedup(t *testing.T) {
	initial := []string{
		"JVMFLAGS=-Xmx256m -XX:-UseContainerSupport",
		"JAVA_TOOL_OPTIONS=-Dfoo=bar -XX:-UseContainerSupport",
		"JMXDISABLE=false",
	}
	env := applyImageCompat(initial, "zk", "confluentinc/cp-zookeeper:6.2.1", "confluentinc/cp-zookeeper:6.2.1", "", "")
	jvmFlags := ""
	javaToolOptions := ""
	jmxDisable := ""
	for _, e := range env {
		k, v := splitEnv(e)
		if k == "JVMFLAGS" {
			jvmFlags = v
		}
		if k == "JAVA_TOOL_OPTIONS" {
			javaToolOptions = v
		}
		if k == "JMXDISABLE" {
			jmxDisable = v
		}
	}
	if jvmFlags != "-Xmx256m -XX:-UseContainerSupport" {
		t.Fatalf("unexpected JVMFLAGS %q", jvmFlags)
	}
	if javaToolOptions != "-Dfoo=bar -XX:-UseContainerSupport" {
		t.Fatalf("unexpected JAVA_TOOL_OPTIONS %q", javaToolOptions)
	}
	if jmxDisable != "false" {
		t.Fatalf("expected existing JMXDISABLE preserved, got %q", jmxDisable)
	}
}
