package main

import (
	"fmt"
	"net/http"
	"runtime"
	"strings"
)

func newRouter(store *containerStore, m *metrics, cfg appConfig, probes *probeState) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/_ping", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/healthz", probes.handleHealthz)
	mux.HandleFunc("/readyz", probes.handleReadyz)
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"Version":       version,
			"ApiVersion":    "1.41",
			"MinAPIVersion": "1.12",
			"GitCommit":     gitCommit,
			"GoVersion":     goVersion,
			"BuildTime":     buildTime,
			"Os":            "linux",
			"Arch":          "amd64",
		})
	})
	mux.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		memTotal := readMemTotal()
		info := map[string]interface{}{
			"ID":              "sidewhale",
			"OperatingSystem": "linux",
			"OSType":          "linux",
			"Architecture":    "amd64",
			"ServerVersion":   version,
			"RuntimeBackend":  cfg.runtimeBackend,
			"MemTotal":        memTotal,
			"NCPU":            runtime.NumCPU(),
			"Name":            "sidewhale",
			"Containers":      len(store.listContainers()),
			"Images":          0,
			"Driver":          "vfs",
		}
		if images, err := listImages(store.stateDir); err == nil {
			info["Images"] = len(images)
		}
		writeJSON(w, http.StatusOK, info)
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fmt.Fprintf(w, "sidewhale_running_containers %d\n", m.running)
		fmt.Fprintf(w, "sidewhale_start_failures %d\n", m.startFailures)
		fmt.Fprintf(w, "sidewhale_pull_duration_ms %d\n", m.pullDurationMs)
		fmt.Fprintf(w, "sidewhale_execution_duration_ms %d\n", m.execDurationMs)
	})

	mux.HandleFunc("/images/create", func(w http.ResponseWriter, r *http.Request) {
		handleImagesCreate(w, r, store, m, cfg, ensureImage)
	})
	mux.HandleFunc("/images/prune", handleImagesPrune)
	mux.HandleFunc("/images/", func(w http.ResponseWriter, r *http.Request) {
		handleImageSubresource(w, r, store.stateDir, cfg.mirrorRules, cfg.enableImageMutations)
	})
	mux.HandleFunc("/images/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		images, err := listImages(store.stateDir)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "image list failed")
			return
		}
		writeJSON(w, http.StatusOK, images)
	})
	mux.HandleFunc("/events", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		handleContainerEvents(w, r)
	})
	mux.HandleFunc("/networks/prune", func(w http.ResponseWriter, r *http.Request) {
		handleNetworksPrune(w, r, store)
	})
	mux.HandleFunc("/networks/create", func(w http.ResponseWriter, r *http.Request) {
		handleNetworksCreate(w, r, store)
	})
	mux.HandleFunc("/networks", func(w http.ResponseWriter, r *http.Request) {
		handleNetworksList(w, r, store)
	})
	mux.HandleFunc("/networks/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/networks/")
		parts := strings.Split(path, "/")
		if len(parts) < 1 || strings.TrimSpace(parts[0]) == "" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		ref := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch action {
		case "":
			if r.Method == http.MethodGet {
				handleNetworkInspect(w, r, store, ref)
				return
			}
			if r.Method == http.MethodDelete {
				handleNetworkDelete(w, r, store, ref)
				return
			}
		case "connect":
			handleNetworkConnect(w, r, store, ref)
			return
		case "disconnect":
			handleNetworkDisconnect(w, r, store, ref)
			return
		}
		writeError(w, http.StatusNotFound, "not found")
	})
	mux.HandleFunc("/volumes/prune", handleVolumesPrune)

	mux.HandleFunc("/containers/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/containers/")
		if path == "prune" {
			handleContainersPrune(w, r)
			return
		}
		if path == "create" && r.Method == http.MethodPost {
			handleContainerCreate(w, r, store, cfg.runtimeBackend, cfg.allowedPrefixes, cfg.mirrorRules, cfg.unixSocketPath, cfg.trustInsecure, ensureImage)
			return
		}
		parts := strings.Split(path, "/")
		if len(parts) < 1 {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		id := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch action {
		case "start":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerStart(w, r, store, m, cfg.limits, cfg.runtimeBackend, cfg.k8sRuntimeNamespace, cfg.k8sImagePullSecrets, id)
		case "kill":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerKill(w, r, store, id)
		case "exec":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecCreate(w, r, store, id)
		case "stop":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerStop(w, r, store, id)
		case "json":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerInspect(w, r, store, id)
		case "logs":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerLogs(w, r, store, id)
		case "stats":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerStats(w, r, store, id)
		case "top":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerTop(w, r, store, id)
		case "archive":
			switch r.Method {
			case http.MethodGet:
				handleArchiveGet(w, r, store, id)
			case http.MethodPut:
				if !cfg.enableArchiveUpload {
					writeError(w, http.StatusNotFound, "not found")
					return
				}
				handleArchivePut(w, r, store, id)
			default:
				writeError(w, http.StatusNotFound, "not found")
			}
		case "wait":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleContainerWait(w, r, store, id)
		default:
			if action == "" && r.Method == http.MethodDelete {
				handleContainerDelete(w, r, store, id)
				return
			}
			writeError(w, http.StatusNotFound, "not found")
		}
	})
	mux.HandleFunc("/exec/", func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/exec/")
		parts := strings.Split(path, "/")
		if len(parts) < 1 || parts[0] == "" {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		id := parts[0]
		action := ""
		if len(parts) > 1 {
			action = parts[1]
		}
		switch action {
		case "start":
			if r.Method != http.MethodPost {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecStart(w, r, store, id)
		case "json":
			if r.Method != http.MethodGet {
				writeError(w, http.StatusNotFound, "not found")
				return
			}
			handleExecJSON(w, r, store, id)
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusNotFound, "not found")
			return
		}
		if cfg.runtimeBackend == runtimeBackendK8s {
			for _, id := range store.listContainerIDs() {
				c, ok := store.findContainer(id)
				if !ok || c == nil || strings.TrimSpace(c.K8sPodName) == "" {
					continue
				}
				_, _ = syncK8sContainerState(r.Context(), store, c)
			}
		}
		list := store.listContainers()
		writeJSON(w, http.StatusOK, list)
	})
	return mux
}
