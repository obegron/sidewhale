package main

import "net/http"

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

func handleNetworksPrune(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"NetworksDeleted": []string{},
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
