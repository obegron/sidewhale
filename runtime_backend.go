package main

import (
	"fmt"
	"strings"
)

const (
	runtimeBackendHost = "host"
	runtimeBackendK8s  = "k8s"
)

func normalizeRuntimeBackend(raw string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(raw))
	if v == "" {
		return runtimeBackendHost, nil
	}
	switch v {
	case runtimeBackendHost, runtimeBackendK8s:
		return v, nil
	default:
		return "", fmt.Errorf("invalid runtime backend %q (supported: %s, %s)", raw, runtimeBackendHost, runtimeBackendK8s)
	}
}
