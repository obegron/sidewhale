package main

import (
	"flag"
	"strings"
	"time"
)

type appConfig struct {
	listenAddr           string
	stateDir             string
	unixSocketPath       string
	runtimeBackend       string
	k8sRuntimeNamespace  string
	k8sImagePullSecrets  []string
	k8sCleanupOrphans    bool
	allowedPrefixes      []string
	mirrorRules          []imageMirrorRule
	trustInsecure        bool
	enableImageMutations bool
	enableArchiveUpload  bool
	limits               runtimeLimits
}

func initConfig() (appConfig, bool, error) {
	listenAddr := flag.String("listen", ":23750", "listen address")
	listenUnix := flag.String("listen-unix", "", "unix socket path (empty = <state-dir>/docker.sock, '-' disables)")
	stateDir := flag.String("state-dir", "/tmp/sidewhale", "state directory")
	runtimeBackend := flag.String("runtime-backend", runtimeBackendHost, "runtime backend: host|k8s")
	k8sRuntimeNamespace := flag.String("k8s-runtime-namespace", "", "namespace for k8s runtime worker pods (default: sidewhale pod namespace)")
	k8sImagePullSecrets := flag.String("k8s-image-pull-secrets", "", "comma-separated imagePullSecrets names for k8s worker pods")
	k8sCleanupOrphans := flag.Bool("k8s-cleanup-orphans", true, "delete orphan sidewhale-managed worker pods during k8s reconcile")
	maxConcurrent := flag.Int("max-concurrent", 4, "max concurrent containers (0 = unlimited)")
	maxRuntime := flag.Duration("max-runtime", 30*time.Minute, "max runtime per container (0 = unlimited)")
	maxLogBytes := flag.Int64("max-log-bytes", 50*1024*1024, "max log size in bytes (0 = unlimited)")
	maxMemBytes := flag.Int64("max-mem-bytes", 0, "soft memory limit in bytes (0 = unlimited)")
	maxDiskBytes := flag.Int64("max-disk-bytes", 2*1024*1024*1024, "max disk usage per container in bytes (0 = unlimited)")
	allowedImages := flag.String("allowed-images", "", "comma-separated allowed image prefixes")
	policyFile := flag.String("image-policy-file", "", "YAML file with allowed image prefixes")
	imageMirrors := flag.String("image-mirrors", "", "comma-separated image rewrite rules from=to")
	mirrorFile := flag.String("image-mirror-file", "", "YAML file with image rewrite rules")
	trustInsecure := flag.Bool("trust-insecure", false, "skip TLS certificate verification for image pulls")
	enableImageMutations := flag.Bool("enable-image-mutations", true, "enable image mutation APIs (tag/push/delete)")
	enableArchiveUpload := flag.Bool("enable-archive-upload", true, "enable PUT /containers/{id}/archive")
	printVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *printVersion {
		return appConfig{}, true, nil
	}

	allowedPrefixes, err := loadAllowedImagePrefixes(*allowedImages, *policyFile)
	if err != nil {
		return appConfig{}, false, err
	}
	mirrorRules, err := loadImageMirrorRules(*imageMirrors, *mirrorFile)
	if err != nil {
		return appConfig{}, false, err
	}
	backend, err := normalizeRuntimeBackend(*runtimeBackend)
	if err != nil {
		return appConfig{}, false, err
	}

	cfg := appConfig{
		listenAddr:           *listenAddr,
		stateDir:             *stateDir,
		unixSocketPath:       resolveUnixSocketPath(*listenUnix, *stateDir),
		runtimeBackend:       backend,
		k8sRuntimeNamespace:  strings.TrimSpace(*k8sRuntimeNamespace),
		k8sImagePullSecrets:  splitCommaList(*k8sImagePullSecrets),
		k8sCleanupOrphans:    *k8sCleanupOrphans,
		allowedPrefixes:      allowedPrefixes,
		mirrorRules:          mirrorRules,
		trustInsecure:        *trustInsecure,
		enableImageMutations: *enableImageMutations,
		enableArchiveUpload:  *enableArchiveUpload,
		limits: runtimeLimits{
			maxConcurrent: *maxConcurrent,
			maxRuntime:    *maxRuntime,
			maxLogBytes:   *maxLogBytes,
			maxMemBytes:   *maxMemBytes,
			maxDiskBytes:  *maxDiskBytes,
		},
	}
	return cfg, false, nil
}

func splitCommaList(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v == "" {
			continue
		}
		out = append(out, v)
	}
	return out
}
