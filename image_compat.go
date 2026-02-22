package main

import (
	"strconv"
	"strings"
)

func applyImageCompat(env []string, hostname, resolvedImage, requestedImage, unixSocketPath, requestHost string) []string {
	if !envHasKey(env, "HOSTNAME") && hostname != "" {
		env = append(env, "HOSTNAME="+hostname)
	}
	if isOracleImage(resolvedImage) || isOracleImage(requestedImage) {
		if !envHasKey(env, "ORACLE_HOSTNAME") {
			env = append(env, "ORACLE_HOSTNAME="+hostname)
		}
	}
	if isRabbitMQImage(resolvedImage) || isRabbitMQImage(requestedImage) {
		if !envHasKey(env, "RABBITMQ_NODENAME") {
			env = append(env, "RABBITMQ_NODENAME=rabbit@"+hostname)
		}
		if !envHasKey(env, "ERL_EPMD_PORT") && isTCPPortInUse(4369) {
			if epmdPort, epmdErr := allocatePort(); epmdErr == nil {
				env = append(env, "ERL_EPMD_PORT="+strconv.Itoa(epmdPort))
			}
		}
		if !envHasKey(env, "RABBITMQ_DIST_PORT") && isTCPPortInUse(25672) {
			if distPort, distErr := allocatePort(); distErr == nil {
				env = append(env, "RABBITMQ_DIST_PORT="+strconv.Itoa(distPort))
			}
		}
	}
	if isConfluentKafkaImage(resolvedImage) || isConfluentKafkaImage(requestedImage) {
		if !envHasKey(env, "ZOOKEEPER_ADMIN_ENABLE_SERVER") {
			env = append(env, "ZOOKEEPER_ADMIN_ENABLE_SERVER=false")
		}
		env = ensureEnvContainsToken(env, "KAFKA_OPTS", "-Dzookeeper.admin.enableServer=false")
	}
	if isKafkaImage(resolvedImage) || isKafkaImage(requestedImage) {
		env = rewriteKafkaListenersForK8s(env)
	}
	if isZookeeperImage(resolvedImage) || isZookeeperImage(requestedImage) {
		// Under proot, JVM container metrics may panic in cgroupv2 detection.
		// Disable container support for zookeeper-family images by default.
		env = ensureEnvContainsToken(env, "JVMFLAGS", "-XX:-UseContainerSupport")
		env = ensureEnvContainsToken(env, "JAVA_TOOL_OPTIONS", "-XX:-UseContainerSupport")
		// Default zookeeper startup enables JMX, which triggers JVM platform
		// metrics initialization and can crash on constrained cgroup layouts.
		// Disable JMX unless the caller explicitly sets it.
		if !envHasKey(env, "JMXDISABLE") {
			env = append(env, "JMXDISABLE=true")
		}
	}
	if isRyukImage(resolvedImage) || isRyukImage(requestedImage) {
		env = mergeEnv(env, []string{"DOCKER_HOST=" + dockerHostForInnerClients(unixSocketPath, requestHost)})
	}
	return env
}

func rewriteKafkaListenersForK8s(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		key, value, ok := strings.Cut(kv, "=")
		if !ok {
			out = append(out, kv)
			continue
		}
		if strings.TrimSpace(key) != "KAFKA_LISTENERS" {
			out = append(out, kv)
			continue
		}
		parts := strings.Split(value, ",")
		for i, part := range parts {
			part = strings.TrimSpace(part)
			lname, rhs, ok := strings.Cut(part, "://")
			if !ok {
				continue
			}
			host, port, ok := strings.Cut(rhs, ":")
			if !ok {
				continue
			}
			host = strings.TrimSpace(host)
			port = strings.TrimSpace(port)
			if port == "" {
				continue
			}
			if host == "" {
				host = "0.0.0.0"
			} else {
				host = "0.0.0.0"
			}
			parts[i] = lname + "://" + host + ":" + port
		}
		out = append(out, key+"="+strings.Join(parts, ","))
	}
	return out
}
