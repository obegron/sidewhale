package main

import (
	"flag"
	"time"
)

type appConfig struct {
	listenAddr      string
	stateDir        string
	unixSocketPath  string
	allowedPrefixes []string
	mirrorRules     []imageMirrorRule
	trustInsecure   bool
	limits          runtimeLimits
}

func initConfig() (appConfig, bool, error) {
	listenAddr := flag.String("listen", ":23750", "listen address")
	listenUnix := flag.String("listen-unix", "", "unix socket path (empty = <state-dir>/docker.sock, '-' disables)")
	stateDir := flag.String("state-dir", "/tmp/sidewhale", "state directory")
	maxConcurrent := flag.Int("max-concurrent", 4, "max concurrent containers (0 = unlimited)")
	maxRuntime := flag.Duration("max-runtime", 30*time.Minute, "max runtime per container (0 = unlimited)")
	maxLogBytes := flag.Int64("max-log-bytes", 50*1024*1024, "max log size in bytes (0 = unlimited)")
	maxMemBytes := flag.Int64("max-mem-bytes", 0, "soft memory limit in bytes (0 = unlimited)")
	allowedImages := flag.String("allowed-images", "", "comma-separated allowed image prefixes")
	policyFile := flag.String("image-policy-file", "", "YAML file with allowed image prefixes")
	imageMirrors := flag.String("image-mirrors", "", "comma-separated image rewrite rules from=to")
	mirrorFile := flag.String("image-mirror-file", "", "YAML file with image rewrite rules")
	trustInsecure := flag.Bool("trust-insecure", false, "skip TLS certificate verification for image pulls")
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

	cfg := appConfig{
		listenAddr:      *listenAddr,
		stateDir:        *stateDir,
		unixSocketPath:  resolveUnixSocketPath(*listenUnix, *stateDir),
		allowedPrefixes: allowedPrefixes,
		mirrorRules:     mirrorRules,
		trustInsecure:   *trustInsecure,
		limits: runtimeLimits{
			maxConcurrent: *maxConcurrent,
			maxRuntime:    *maxRuntime,
			maxLogBytes:   *maxLogBytes,
			maxMemBytes:   *maxMemBytes,
		},
	}
	return cfg, false, nil
}
