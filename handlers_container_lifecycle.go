package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func handleCreate(w http.ResponseWriter, r *http.Request, store *containerStore, runtimeBackend string, allowedPrefixes []string, mirrorRules []imageMirrorRule, unixSocketPath string, trustInsecure bool, ensureImage func(context.Context, string, string, *metrics, bool) (string, imageMeta, error)) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if strings.TrimSpace(req.Image) == "" {
		writeError(w, http.StatusBadRequest, "missing image")
		return
	}
	if isRyukImage(req.Image) {
		runtimeBackend = runtimeBackendHost
	}
	resolvedRef := rewriteImageReference(req.Image, mirrorRules)
	if !isImageAllowed(resolvedRef, allowedPrefixes) {
		writeError(w, http.StatusForbidden, "image not allowed by policy")
		return
	}
	if runtimeBackend == runtimeBackendHost && (isOracleImage(req.Image) || isOracleImage(resolvedRef)) {
		writeError(w, http.StatusBadRequest, "oracle images are not supported on host/proot backend; use --runtime-backend=k8s")
		return
	}
	name := normalizeContainerName(r.URL.Query().Get("name"))
	if name != "" && store.nameInUse(name) {
		writeError(w, http.StatusConflict, "container name already in use")
		return
	}

	var (
		imageRootfs string
		meta        imageMeta
		err         error
	)
	if runtimeBackend != runtimeBackendK8s {
		imageRootfs, meta, _, err = ensureImageWithFallback(
			r.Context(),
			resolvedRef,
			req.Image,
			store.stateDir,
			nil,
			trustInsecure,
			ensureImage,
		)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	id, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	hostname := normalizeContainerHostname(req.Hostname)
	if hostname == "" {
		hostname = defaultContainerHostname(id)
	}

	rootfs := filepath.Join(store.stateDir, "containers", id, "rootfs")
	if err := os.MkdirAll(rootfs, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "rootfs allocation failed")
		return
	}
	if runtimeBackend != runtimeBackendK8s {
		if err := copyDir(imageRootfs, rootfs); err != nil {
			writeError(w, http.StatusInternalServerError, "rootfs copy failed")
			return
		}
		if err := writeContainerIdentityFiles(rootfs, hostname); err != nil {
			writeError(w, http.StatusInternalServerError, "hostname setup failed")
			return
		}
	}
	logPath := filepath.Join(store.stateDir, "containers", id, "container.log")
	stdoutPath := filepath.Join(store.stateDir, "containers", id, "stdout.log")
	stderrPath := filepath.Join(store.stateDir, "containers", id, "stderr.log")
	tmpPath := filepath.Join(store.stateDir, "containers", id, "tmp")
	if err := os.MkdirAll(tmpPath, 0o777); err != nil {
		writeError(w, http.StatusInternalServerError, "tmp allocation failed")
		return
	}
	if err := os.Chmod(tmpPath, 0o1777); err != nil {
		writeError(w, http.StatusInternalServerError, "tmp allocation failed")
		return
	}

	entrypoint := req.Entrypoint
	cmd := req.Cmd
	if len(entrypoint) == 0 {
		entrypoint = meta.Entrypoint
	}
	if len(cmd) == 0 {
		cmd = meta.Cmd
	}
	if len(req.Entrypoint) > 0 {
		entrypoint = req.Entrypoint
		cmd = req.Cmd
	}

	env := mergeEnv(meta.Env, req.Env)
	env = applyImageCompat(env, hostname, resolvedRef, req.Image, unixSocketPath, r.Host)
	workingDir := req.WorkingDir
	if workingDir == "" {
		workingDir = meta.WorkingDir
	}
	if workingDir == "" && runtimeBackend != runtimeBackendK8s {
		workingDir = "/"
	}

	allExposed := mergeExposedPorts(meta.ExposedPorts, req.ExposedPorts)
	ports, err := resolvePortBindings(allExposed, req.ExposedPorts, req.HostConfig.PortBindings)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	runtimeImageRef := resolvedRef
	if runtimeBackend == runtimeBackendK8s {
		// In k8s backend, let kubelet resolve/pull original image references.
		// This keeps image cache behavior native to Kubernetes and avoids
		// sidewhale mirror rewrite prefixes leaking into Pod specs.
		runtimeImageRef = req.Image
	}

	c := &Container{
		ID:            id,
		Name:          name,
		Hostname:      hostname,
		User:          firstNonEmpty(strings.TrimSpace(req.User), strings.TrimSpace(meta.User)),
		Image:         req.Image,
		ResolvedImage: runtimeImageRef,
		Rootfs:        rootfs,
		Created:       time.Now().UTC(),
		Running:       false,
		ExitCode:      0,
		Ports:         ports,
		ExposedPorts:  allExposed,
		Env:           env,
		WorkingDir:    workingDir,
		LogPath:       logPath,
		StdoutPath:    stdoutPath,
		StderrPath:    stderrPath,
		Cmd:           append(entrypoint, cmd...),
		Entrypoint:    append([]string{}, entrypoint...),
		Args:          append([]string{}, cmd...),
		NetworkMode:   "bridge",
		ExtraHosts:    normalizeExtraHosts(req.HostConfig.ExtraHosts),
	}

	requestedMode := strings.TrimSpace(req.HostConfig.NetworkMode)
	if requestedMode != "" {
		c.NetworkMode = requestedMode
	}
	if strings.EqualFold(c.NetworkMode, "default") {
		c.NetworkMode = "bridge"
	}

	attachedToNetwork := false
	for networkRef, endpoint := range req.NetworkingConfig.EndpointsConfig {
		networkRef = strings.TrimSpace(networkRef)
		if networkRef == "" {
			continue
		}
		if strings.EqualFold(networkRef, "default") {
			networkRef = "bridge"
		}
		n, ok := store.findNetwork(networkRef)
		if !ok {
			writeError(w, http.StatusNotFound, "network not found")
			return
		}
		if err := store.connectContainerToNetwork(n.ID, c, endpoint.Aliases); err != nil {
			writeError(w, http.StatusInternalServerError, "network attach failed")
			return
		}
		attachedToNetwork = true
		if strings.TrimSpace(req.HostConfig.NetworkMode) == "" || strings.EqualFold(c.NetworkMode, "default") {
			c.NetworkMode = n.Name
		}
	}

	if !attachedToNetwork {
		switch strings.ToLower(strings.TrimSpace(c.NetworkMode)) {
		case "", "default", "bridge":
			c.NetworkMode = "bridge"
			if err := store.connectContainerToNetwork(builtInBridgeNetworkID, c, nil); err != nil {
				writeError(w, http.StatusInternalServerError, "network attach failed")
				return
			}
		case "host", "none":
		default:
			n, ok := store.findNetwork(c.NetworkMode)
			if !ok {
				writeError(w, http.StatusNotFound, "network not found")
				return
			}
			if err := store.connectContainerToNetwork(n.ID, c, nil); err != nil {
				writeError(w, http.StatusInternalServerError, "network attach failed")
				return
			}
		}
	}

	if err := store.saveContainer(c); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	writeJSON(w, http.StatusCreated, createResponse{ID: id, Warnings: nil})
}

func handleStart(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, limits runtimeLimits, runtimeBackend, k8sRuntimeNamespace string, k8sImagePullSecrets []string, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if c.Running {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if isRyukImage(c.Image) {
		runtimeBackend = runtimeBackendHost
	}
	if limits.maxConcurrent > 0 {
		// Reconcile runtime count from persisted container state to avoid
		// stale in-memory counters producing false 409 conflicts.
		currentRunning := store.runningCount()
		m.mu.Lock()
		m.running = currentRunning
		if m.running >= limits.maxConcurrent {
			m.mu.Unlock()
			writeError(w, http.StatusConflict, "max concurrent containers reached")
			return
		}
		m.running++
		m.mu.Unlock()
	}
	reserved := limits.maxConcurrent > 0
	if runtimeBackend == runtimeBackendK8s {
		client, err := newInClusterK8sClient()
		if err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		if ns := strings.TrimSpace(k8sRuntimeNamespace); ns != "" {
			client.namespace = ns
		}
		client.imagePullSecrets = append([]string{}, k8sImagePullSecrets...)
		if c.K8sPodName == "" {
			hostAliasMap := mergeContainerHostAliases(store.peerHostAliasesForContainer(c.ID), c.ExtraHosts)
			podName, err := client.createPod(r.Context(), c, hostAliasMap)
			if err != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				m.mu.Lock()
				m.startFailures++
				m.mu.Unlock()
				writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
				return
			}
			c.K8sPodName = podName
			c.K8sNamespace = client.namespace
			if err := store.saveContainer(c); err != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				writeError(w, http.StatusInternalServerError, "state write failed")
				return
			}
		}
		podIP, podState, err := client.waitForPodStarted(r.Context(), c.K8sNamespace, c.K8sPodName, 2*time.Minute)
		if err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			m.mu.Lock()
			m.startFailures++
			m.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		if err := syncContainerTmpToK8sPod(r.Context(), client, c); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			m.mu.Lock()
			m.startFailures++
			m.mu.Unlock()
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		targets := map[int]string{}
		if podState.Running {
			for cp := range c.Ports {
				targets[cp] = fmt.Sprintf("%s:%d", podIP, cp)
			}
			store.stopProxies(c.ID)
			proxies, err := startPortProxies(c.Ports, targets)
			if err != nil {
				if reserved {
					m.mu.Lock()
					if m.running > 0 {
						m.running--
					}
					m.mu.Unlock()
				}
				m.mu.Lock()
				m.startFailures++
				m.mu.Unlock()
				writeError(w, http.StatusInternalServerError, "port proxy failed")
				return
			}
			store.setProxies(c.ID, proxies)
		}
		c.Running = podState.Running
		c.Pid = 0
		c.ExitCode = podState.ExitCode
		if podState.StartedAt.IsZero() {
			c.StartedAt = time.Now().UTC()
		} else {
			c.StartedAt = podState.StartedAt
		}
		c.FinishedAt = podState.FinishedAt
		c.K8sPodIP = podIP
		c.PortTargets = targets
		if err := store.saveContainer(c); err != nil {
			store.stopProxies(c.ID)
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "state write failed")
			return
		}
		startedAt := time.Now()
		go monitorK8sPod(c.ID, c.K8sNamespace, c.K8sPodName, store, m, startedAt)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	cmdArgs := c.Cmd
	if len(cmdArgs) == 0 {
		cmdArgs = []string{"sleep", "3600"}
	}
	cmdArgs = resolveCommandInRootfs(c.Rootfs, c.Env, cmdArgs)
	runtimeEnv := append([]string{}, c.Env...)
	runtimeTargets := clonePortTargets(c.PortTargets)
	ensureLoopbackIP := func() error {
		_, err := ensureContainerLoopbackIP(store, c)
		return err
	}
	if isRedisImage(c.Image) {
		if err := ensureLoopbackIP(); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		cmdArgs = applyRedisRuntimeCompat(cmdArgs, c.LoopbackIP)
		runtimeTargets[6379] = c.LoopbackIP + ":6379"
	}
	if isLLdapImage(c.Image) {
		if err := ensureLoopbackIP(); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		runtimeEnv = applyLLdapRuntimeCompatEnv(runtimeEnv, c.LoopbackIP)
		runtimeTargets[3890] = c.LoopbackIP + ":3890"
		runtimeTargets[17170] = c.LoopbackIP + ":17170"
	}
	if isNginxImage(c.Image) {
		if err := ensureLoopbackIP(); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		if err := writeNginxCompatConfig(c.Rootfs, 8080); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: nginx compat failed")
			return
		}
		cmdArgs = applyNginxRuntimeCompatCommand(cmdArgs, 8080)
		runtimeTargets[80] = c.LoopbackIP + ":8080"
	}
	if isSSHDImage(c.Image) {
		if err := ensureLoopbackIP(); err != nil {
			if reserved {
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.mu.Unlock()
			}
			writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
			return
		}
		const sshdCompatPort = 2222
		cmdArgs = applySSHDRuntimeCompat(cmdArgs, c.LoopbackIP, sshdCompatPort)
		runtimeTargets[22] = fmt.Sprintf("%s:%d", c.LoopbackIP, sshdCompatPort)
	}

	socketBinds, err := dockerSocketBindsForContainer(c, unixSocketPathFromContainerEnv(c.Env))
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}
	if err := os.Chmod(containerTmpDir(c), 0o1777); err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: tmp permission fix failed")
		return
	}
	if err := writeContainerIdentityFilesWithAliasesAndHosts(c.Rootfs, c.Hostname, store.peerAliasesForContainer(c.ID), c.ExtraHosts); err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: hosts update failed")
		return
	}

	cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), c.WorkingDir, c.User, socketBinds, cmdArgs)
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	runtimeEnv = applyTiniRuntimeCompatEnv(runtimeEnv, cmdArgs)
	cmd.Env = deduplicateEnv(append(os.Environ(), runtimeEnv...))

	logFile, err := os.OpenFile(c.LogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	stdoutPath := c.StdoutPath
	if strings.TrimSpace(stdoutPath) == "" {
		stdoutPath = c.LogPath
	}
	stderrPath := c.StderrPath
	if strings.TrimSpace(stderrPath) == "" {
		stderrPath = c.LogPath
	}
	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		logFile.Close()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	stderrFile, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		stdoutFile.Close()
		logFile.Close()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "log open failed")
		return
	}
	closeLogs := func() {
		_ = stderrFile.Close()
		_ = stdoutFile.Close()
		_ = logFile.Close()
	}
	cmd.Stdout = io.MultiWriter(logFile, stdoutFile)
	cmd.Stderr = io.MultiWriter(logFile, stderrFile)

	fmt.Printf("sidewhale: starting container %s (id %s)\n", c.Name, c.ID)
	fmt.Printf("sidewhale: command: %s %s\n", cmd.Path, strings.Join(cmd.Args[1:], " "))

	if err := cmd.Start(); err != nil {
		closeLogs()
		m.mu.Lock()
		m.startFailures++
		if reserved && m.running > 0 {
			m.running--
		}
		m.mu.Unlock()
		writeError(w, http.StatusInternalServerError, "start failed: "+err.Error())
		return
	}

	proxies, err := startPortProxies(c.Ports, runtimeTargets)
	if err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		closeLogs()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "port proxy failed")
		return
	}
	store.setProxies(c.ID, proxies)

	c.Running = true
	c.Pid = cmd.Process.Pid
	c.ExitCode = 0
	c.StartedAt = time.Now().UTC()
	c.FinishedAt = time.Time{}
	c.PortTargets = runtimeTargets
	if err := store.saveContainer(c); err != nil {
		_ = killProcessGroup(cmd.Process.Pid, syscall.SIGKILL)
		store.stopProxies(c.ID)
		closeLogs()
		if reserved {
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.mu.Unlock()
		}
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	refreshNetworkAliasHosts(store, c.ID)

	startedAt := time.Now()

	go func() {
		waitErr := cmd.Wait()
		exitCode := 0
		if waitErr != nil {
			var exitErr *exec.ExitError
			if errors.As(waitErr, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = 126
			}
		}
		closeLogs()
		store.stopProxies(c.ID)
		finishedAt := time.Now().UTC()
		store.markStoppedWithExit(c.ID, &exitCode, finishedAt)
		m.mu.Lock()
		if m.running > 0 {
			m.running--
		}
		m.execDurationMs = time.Since(startedAt).Milliseconds()
		m.mu.Unlock()
	}()

	go monitorContainer(c.ID, c.Pid, c.LogPath, store, limits)

	w.WriteHeader(http.StatusNoContent)
}

func handleStop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err == nil {
			_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 2)
		}
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !c.Running || c.Pid == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	terminateProcessTree(c.Pid, 2*time.Second)
	store.stopProxies(c.ID)
	exitCode := 137
	store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	w.WriteHeader(http.StatusNoContent)
}

func handleKill(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err == nil {
			_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 0)
		}
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !c.Running || c.Pid == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	terminateProcessTree(c.Pid, 0)
	store.stopProxies(c.ID)
	exitCode := 137
	store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	w.WriteHeader(http.StatusNoContent)
}

func handleDelete(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if c.Running {
		if strings.TrimSpace(c.K8sPodName) != "" {
			client, err := newInClusterK8sClient()
			if err == nil {
				_ = client.deletePod(r.Context(), c.K8sNamespace, c.K8sPodName, 2)
			}
		} else {
			terminateProcessTree(c.Pid, 2*time.Second)
		}
		store.stopProxies(c.ID)
		exitCode := 137
		store.markStoppedWithExit(c.ID, &exitCode, time.Now().UTC())
	}

	_ = os.RemoveAll(filepath.Dir(c.Rootfs))
	_ = os.Remove(c.LogPath)
	_ = os.Remove(c.StdoutPath)
	_ = os.Remove(c.StderrPath)
	_ = os.Remove(store.containerPath(c.ID))

	store.mu.Lock()
	delete(store.containers, c.ID)
	store.mu.Unlock()
	store.disconnectContainerFromAllNetworks(c.ID)

	w.WriteHeader(http.StatusNoContent)
}
