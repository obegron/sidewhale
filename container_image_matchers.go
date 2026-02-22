package main

import "strings"

func isRyukImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "/ryuk:") || strings.HasSuffix(image, "/ryuk")
}

func isRabbitMQImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "rabbitmq")
}

func isOracleImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "oracle")
}

func isConfluentKafkaImage(image string) bool {
	image = normalizeImageToken(image)
	return strings.Contains(image, "confluentinc/cp-kafka")
}

func isRedisImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "redis")
}

func isLLdapImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "lldap/lldap")
}

func isNginxImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "/nginx:") || strings.HasSuffix(image, "/nginx")
}

func isSSHDImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "testcontainers/sshd")
}

func isZookeeperImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "/zookeeper:") ||
		strings.HasSuffix(image, "/zookeeper") ||
		strings.Contains(image, "cp-zookeeper")
}

func isCassandraImage(image string) bool {
	image = strings.ToLower(normalizeImageToken(image))
	return strings.Contains(image, "/cassandra:") ||
		strings.HasPrefix(image, "cassandra:") ||
		strings.HasSuffix(image, "/cassandra") ||
		image == "cassandra"
}

func dockerHostForInnerClients(unixSocketPath, requestHost string) string {
	if strings.TrimSpace(unixSocketPath) != "" {
		return "unix://" + unixSocketPath
	}
	host := strings.TrimSpace(requestHost)
	if host == "" {
		host = "127.0.0.1:23750"
	}
	if strings.HasPrefix(host, "tcp://") || strings.HasPrefix(host, "http://") || strings.HasPrefix(host, "https://") {
		return host
	}
	return "tcp://" + host
}

func unixSocketPathFromContainerEnv(env []string) string {
	for _, kv := range env {
		if !strings.HasPrefix(kv, "DOCKER_HOST=") {
			continue
		}
		val := strings.TrimPrefix(kv, "DOCKER_HOST=")
		if strings.HasPrefix(val, "unix://") {
			return strings.TrimPrefix(val, "unix://")
		}
	}
	return ""
}

func dockerSocketBindsForContainer(c *Container, socketPath string) ([]string, error) {
	socketPath = strings.TrimSpace(socketPath)
	if socketPath == "" || c == nil {
		return nil, nil
	}
	binds := []string{socketPath + ":" + socketPath}
	if socketPath != "/var/run/docker.sock" {
		binds = append(binds, socketPath+":/var/run/docker.sock")
	}
	if socketPath != "/run/docker.sock" {
		binds = append(binds, socketPath+":/run/docker.sock")
	}
	return binds, nil
}
