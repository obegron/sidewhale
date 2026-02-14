package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestEventsEndpointReturnsEventObject(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /events status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("GET /events invalid json: %v", err)
	}
	if payload["Type"] != "container" {
		t.Fatalf("GET /events payload Type=%v, want container", payload["Type"])
	}
	if payload["Action"] != "noop" {
		t.Fatalf("GET /events payload Action=%v, want noop", payload["Action"])
	}
}

func TestTopEndpointReturnsProcessShape(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Image:   "alpine:3.20",
				Cmd:     []string{"sleep", "10"},
				Created: time.Now().UTC(),
			},
		},
		execs:    map[string]*ExecInstance{},
		proxies:  map[string][]*portProxy{},
		stateDir: t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/top", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /containers/{id}/top status = %d, want %d", rec.Code, http.StatusOK)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("invalid top payload json: %v", err)
	}
	if _, ok := payload["Titles"]; !ok {
		t.Fatalf("top payload missing Titles: %s", rec.Body.String())
	}
	if _, ok := payload["Processes"]; !ok {
		t.Fatalf("top payload missing Processes: %s", rec.Body.String())
	}
}

func TestPruneEndpointsReturnDockerShape(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	tests := []struct {
		path         string
		expectedKeys []string
	}{
		{path: "/containers/prune", expectedKeys: []string{"ContainersDeleted", "SpaceReclaimed"}},
		{path: "/images/prune", expectedKeys: []string{"ImagesDeleted", "SpaceReclaimed"}},
		{path: "/networks/prune", expectedKeys: []string{"NetworksDeleted"}},
		{path: "/volumes/prune", expectedKeys: []string{"VolumesDeleted", "SpaceReclaimed"}},
	}

	for _, tt := range tests {
		req := httptest.NewRequest(http.MethodPost, tt.path, nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s status = %d, want %d", tt.path, rec.Code, http.StatusOK)
		}
		var payload map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
			t.Fatalf("POST %s invalid json: %v", tt.path, err)
		}
		for _, key := range tt.expectedKeys {
			if _, ok := payload[key]; !ok {
				t.Fatalf("POST %s payload missing key %q: %s", tt.path, key, rec.Body.String())
			}
		}
	}
}

func TestImageMutationEndpointsCanBeDisabled(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir, enableImageMutations: false}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodPost, "/images/alpine/tag?repo=example.local/test&tag=latest", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST /images/{name}/tag status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestArchiveUploadCanBeDisabled(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir, enableArchiveUpload: false}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	req := httptest.NewRequest(http.MethodPut, "/containers/abc/archive?path=/tmp", bytes.NewReader(nil))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("PUT /containers/{id}/archive status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}
