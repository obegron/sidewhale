package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

func handleNetworksCreate(w http.ResponseWriter, r *http.Request, store *containerStore) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	var req networkCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "network name required")
		return
	}
	if existing, ok := store.getNetwork(name); ok && req.CheckDuplicate {
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"Id":      existing.ID,
			"Warning": "network already exists",
		})
		return
	}
	id, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	n := &Network{
		ID:         id,
		Name:       name,
		Driver:     firstNonEmpty(strings.TrimSpace(req.Driver), "bridge"),
		Scope:      "local",
		Created:    time.Now().UTC().Format(time.RFC3339Nano),
		Internal:   req.Internal,
		Attachable: req.Attachable,
		Ingress:    req.Ingress,
		EnableIPv6: req.EnableIPv6,
		IPAM:       req.IPAM,
		Options:    req.Options,
		Labels:     req.Labels,
		Containers: map[string]*NetworkEndpoint{},
	}
	if n.IPAM == nil {
		n.IPAM = map[string]interface{}{
			"Driver":  "default",
			"Config":  []interface{}{},
			"Options": map[string]string{},
		}
	}
	if n.Options == nil {
		n.Options = map[string]string{}
	}
	if n.Labels == nil {
		n.Labels = map[string]string{}
	}
	if err := store.saveNetwork(n); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"Id":      n.ID,
		"Warning": "",
	})
}

func handleNetworksList(w http.ResponseWriter, r *http.Request, store *containerStore) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	writeJSON(w, http.StatusOK, store.listNetworks())
}

func handleNetworkInspect(w http.ResponseWriter, r *http.Request, store *containerStore, ref string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	n, ok := store.getNetwork(ref)
	if !ok {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func handleNetworkDelete(w http.ResponseWriter, r *http.Request, store *containerStore, ref string) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	n, ok := store.getNetwork(ref)
	if !ok {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	if n.ID == builtInBridgeNetworkID {
		writeError(w, http.StatusForbidden, "cannot delete default network")
		return
	}
	if len(n.Containers) > 0 {
		writeError(w, http.StatusConflict, "network has active endpoints")
		return
	}
	store.mu.Lock()
	delete(store.networks, n.ID)
	store.mu.Unlock()
	_ = os.Remove(store.networkPath(n.ID))
	w.WriteHeader(http.StatusNoContent)
}

func handleNetworkConnect(w http.ResponseWriter, r *http.Request, store *containerStore, ref string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	n, ok := store.getNetwork(ref)
	if !ok {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	var req networkConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, ok := store.get(req.Container)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if err := store.connectContainerToNetwork(n.ID, c, req.EndpointConfig.Aliases); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func handleNetworkDisconnect(w http.ResponseWriter, r *http.Request, store *containerStore, ref string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	n, ok := store.getNetwork(ref)
	if !ok {
		writeError(w, http.StatusNotFound, "network not found")
		return
	}
	var req networkDisconnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	c, ok := store.get(req.Container)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	if err := store.disconnectContainerFromNetwork(n.ID, c.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}
	w.WriteHeader(http.StatusOK)
}
