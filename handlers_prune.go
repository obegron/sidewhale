package main

import (
	"net/http"
	"os"
)

func handleContainersPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ContainersDeleted": []string{},
		"SpaceReclaimed":    int64(0),
	})
}

func handleImagesPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ImagesDeleted":  []interface{}{},
		"SpaceReclaimed": int64(0),
	})
}

func handleNetworksPrune(w http.ResponseWriter, r *http.Request, store *containerStore) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	deleted := []string{}
	if store != nil {
		store.mu.Lock()
		for id, n := range store.networks {
			if id == builtInBridgeNetworkID {
				continue
			}
			if len(n.Containers) > 0 {
				continue
			}
			deleted = append(deleted, n.Name)
			delete(store.networks, id)
			_ = os.Remove(store.networkPath(id))
		}
		store.mu.Unlock()
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"NetworksDeleted": deleted,
	})
}

func handleVolumesPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"VolumesDeleted": []string{},
		"SpaceReclaimed": int64(0),
	})
}
