package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"
)

func handleJSON(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if strings.TrimSpace(c.K8sPodName) != "" {
		if synced, err := syncK8sContainerState(r.Context(), store, c); err == nil && synced != nil {
			c = synced
		}
	}
	exposed := c.ExposedPorts
	if len(exposed) == 0 {
		exposed = make(map[string]struct{}, len(c.Ports))
		for internal := range c.Ports {
			exposed[fmt.Sprintf("%d/tcp", internal)] = struct{}{}
		}
	}
	path := firstArg(c.Cmd)
	args := restArgs(c.Cmd)
	networks := store.networkSettingsForContainer(c.ID)
	networkMode := strings.TrimSpace(c.NetworkMode)
	if networkMode == "" {
		networkMode = "bridge"
	}
	if strings.TrimSpace(c.K8sPodName) != "" && strings.TrimSpace(c.K8sPodIP) != "" {
		if bridgeRaw, ok := networks["bridge"]; ok {
			if bridge, ok := bridgeRaw.(map[string]interface{}); ok {
				bridge["IPAddress"] = c.K8sPodIP
				bridge["IPPrefixLen"] = 24
			}
		}
	}
	switch strings.ToLower(networkMode) {
	case "none", "host":
		networks = map[string]interface{}{
			strings.ToLower(networkMode): map[string]interface{}{
				"NetworkID":           strings.ToLower(networkMode),
				"EndpointID":          "",
				"Gateway":             "",
				"IPAddress":           "",
				"IPPrefixLen":         0,
				"IPv6Gateway":         "",
				"GlobalIPv6Address":   "",
				"GlobalIPv6PrefixLen": 0,
				"MacAddress":          "",
				"Aliases":             []string{},
			},
		}
	}
	resp := map[string]interface{}{
		"Id":      c.ID,
		"Name":    containerDisplayName(c),
		"Created": c.Created.Format(time.RFC3339Nano),
		"Path":    path,
		"Args":    args,
		"State": map[string]interface{}{
			"Status":     statusFromRunning(c.Running),
			"Running":    c.Running,
			"Paused":     false,
			"Restarting": false,
			"OOMKilled":  false,
			"Dead":       false,
			"Pid":        c.Pid,
			"ExitCode":   c.ExitCode,
			"Error":      "",
			"StartedAt":  containerStartedAt(c).Format(time.RFC3339Nano),
			"FinishedAt": containerFinishedAt(c).Format(time.RFC3339Nano),
		},
		"Config": map[string]interface{}{
			"Hostname":     c.Hostname,
			"User":         c.User,
			"Image":        c.Image,
			"Env":          c.Env,
			"Cmd":          args,
			"Entrypoint":   []string{path},
			"WorkingDir":   c.WorkingDir,
			"ExposedPorts": exposed,
		},
		"HostConfig": map[string]interface{}{
			"NetworkMode":  networkMode,
			"PortBindings": toDockerPorts(c.Ports),
		},
		"Mounts": []map[string]interface{}{},
		"NetworkSettings": map[string]interface{}{
			"Ports":    toDockerPorts(c.Ports),
			"Networks": networks,
		},
	}
	writeJSON(w, http.StatusOK, resp)
}

func handleTop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	procLine := []string{"0", statusFromRunning(c.Running), strings.Join(c.Cmd, " ")}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Titles":    []string{"PID", "STATE", "COMMAND"},
		"Processes": [][]string{procLine},
	})
}

func handleEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	now := time.Now().UTC()
	evt := map[string]interface{}{
		"status": "noop",
		"id":     "sidewhale",
		"from":   "sidewhale",
		"Type":   "container",
		"Action": "noop",
		"Actor": map[string]interface{}{
			"ID":         "sidewhale",
			"Attributes": map[string]string{},
		},
		"time":     now.Unix(),
		"timeNano": now.UnixNano(),
	}
	enc := json.NewEncoder(w)
	_ = enc.Encode(evt)
}

func handleLogs(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	includeStdout := parseDockerBool(r.URL.Query().Get("stdout"), true)
	includeStderr := parseDockerBool(r.URL.Query().Get("stderr"), true)
	if !includeStdout && !includeStderr {
		w.WriteHeader(http.StatusOK)
		return
	}
	follow := parseDockerBool(r.URL.Query().Get("follow"), false)
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
		w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
		flusher, _ := w.(http.Flusher)
		lastSize := 0
		sendDelta := func(full []byte) {
			if len(full) <= lastSize {
				return
			}
			delta := full[lastSize:]
			lastSize = len(full)
			if includeStdout {
				_, _ = w.Write(frameDockerRawStream(1, delta))
			}
			if includeStderr {
				_, _ = w.Write(frameDockerRawStream(2, delta))
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		for {
			logs, err := client.podLogs(r.Context(), c.K8sNamespace, c.K8sPodName)
			if err == nil {
				sendDelta(logs)
			}
			if !follow {
				return
			}
			current, ok := store.findContainer(id)
			if !ok || !current.Running {
				// One last flush attempt after exit to avoid tail truncation.
				logs, err := client.podLogs(r.Context(), c.K8sNamespace, c.K8sPodName)
				if err == nil {
					sendDelta(logs)
				}
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(200 * time.Millisecond):
			}
		}
	}
	type logStream struct {
		stream byte
		file   *os.File
		offset int64
	}
	streams := make([]*logStream, 0, 2)
	addStream := func(path string, stream byte) error {
		logFile, err := os.Open(path)
		if err != nil {
			return err
		}
		streams = append(streams, &logStream{stream: stream, file: logFile})
		return nil
	}
	logPath := c.LogPath
	stdoutPath := c.StdoutPath
	if strings.TrimSpace(stdoutPath) == "" {
		stdoutPath = logPath
	}
	stderrPath := c.StderrPath
	if strings.TrimSpace(stderrPath) == "" {
		stderrPath = logPath
	}
	if includeStdout {
		if err := addStream(stdoutPath, 1); err != nil {
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
	}
	if includeStderr {
		if stdoutPath == stderrPath && includeStdout {
			// Backward-compat for legacy containers with a single merged logfile.
		} else if err := addStream(stderrPath, 2); err != nil {
			for _, s := range streams {
				_ = s.file.Close()
			}
			writeError(w, http.StatusInternalServerError, "log read failed")
			return
		}
	}
	for _, s := range streams {
		defer s.file.Close()
	}

	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)

	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	writeNew := func() error {
		for _, s := range streams {
			stat, err := s.file.Stat()
			if err != nil {
				return err
			}
			size := stat.Size()
			if size <= s.offset {
				continue
			}
			chunk := make([]byte, size-s.offset)
			n, err := s.file.ReadAt(chunk, s.offset)
			if err != nil && !errors.Is(err, io.EOF) {
				return err
			}
			s.offset += int64(n)
			if n == 0 {
				continue
			}
			_, _ = w.Write(frameDockerRawStream(s.stream, chunk[:n]))
		}
		flush()
		return nil
	}

	if err := writeNew(); err != nil {
		return
	}
	if !follow {
		return
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			if err := writeNew(); err != nil {
				return
			}
			current, ok := store.findContainer(id)
			if !ok || !current.Running {
				_ = writeNew()
				return
			}
		}
	}
}

func handleStats(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}

	now := time.Now().UTC()
	memUsage, _ := readRSS(c.Pid)
	if !c.Running {
		memUsage = 0
	}
	memLimit := readMemTotal()
	if memLimit == 0 {
		memLimit = 1
	}
	payload := map[string]interface{}{
		"read":      now.Format(time.RFC3339Nano),
		"preread":   now.Format(time.RFC3339Nano),
		"id":        c.ID,
		"name":      containerDisplayName(c),
		"num_procs": 1,
		"pids_stats": map[string]interface{}{
			"current": 1,
		},
		"cpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage":         0,
				"percpu_usage":        []int64{},
				"usage_in_kernelmode": 0,
				"usage_in_usermode":   0,
			},
			"system_cpu_usage": 0,
			"online_cpus":      runtime.NumCPU(),
		},
		"precpu_stats": map[string]interface{}{
			"cpu_usage": map[string]interface{}{
				"total_usage":  0,
				"percpu_usage": []int64{},
			},
			"system_cpu_usage": 0,
			"online_cpus":      runtime.NumCPU(),
		},
		"memory_stats": map[string]interface{}{
			"usage": memUsage,
			"limit": memLimit,
			"stats": map[string]interface{}{},
		},
		"networks": map[string]interface{}{},
		"blkio_stats": map[string]interface{}{
			"io_service_bytes_recursive": []interface{}{},
			"io_serviced_recursive":      []interface{}{},
		},
	}

	stream := parseDockerBool(r.URL.Query().Get("stream"), true)
	if !stream {
		writeJSON(w, http.StatusOK, payload)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(payload)
}

func handleWait(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	condition := strings.TrimSpace(r.URL.Query().Get("condition"))
	if condition == "" {
		condition = "not-running"
	}
	switch condition {
	case "not-running", "next-exit", "removed":
	default:
		writeError(w, http.StatusBadRequest, "unsupported wait condition")
		return
	}

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		c, ok := store.findContainer(id)
		if !ok {
			if condition == "removed" {
				writeJSON(w, http.StatusOK, map[string]interface{}{"StatusCode": 0, "Error": nil})
				return
			}
			writeError(w, http.StatusNotFound, "container not found")
			return
		}
		if strings.TrimSpace(c.K8sPodName) != "" {
			if synced, err := syncK8sContainerState(r.Context(), store, c); err == nil && synced != nil {
				c = synced
			}
		}
		if c.Running && strings.TrimSpace(c.K8sPodName) == "" && !processAlive(c.Pid) {
			store.markStopped(c.ID)
			c, _ = store.findContainer(id)
		}
		if c == nil || !c.Running {
			exitCode := 0
			if c != nil {
				exitCode = c.ExitCode
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{"StatusCode": exitCode, "Error": nil})
			return
		}

		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}
