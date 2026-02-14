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
		networks:   map[string]*Network{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	cfg := appConfig{stateDir: store.stateDir}
	if err := store.init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
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

func TestNetworkEndpointsCreateConnectInspect(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Name:    "alpha",
				Image:   "alpine:3.20",
				Created: time.Now().UTC(),
			},
		},
		networks: map[string]*Network{},
		execs:    map[string]*ExecInstance{},
		proxies:  map[string][]*portProxy{},
		stateDir: t.TempDir(),
	}
	if err := store.init(); err != nil {
		t.Fatalf("store init: %v", err)
	}
	cfg := appConfig{stateDir: store.stateDir}
	handler := timeoutMiddleware(apiVersionMiddleware(newRouter(store, &metrics{}, cfg, &probeState{})))

	createReq := httptest.NewRequest(http.MethodPost, "/networks/create", bytes.NewBufferString(`{"Name":"tcnet","CheckDuplicate":true}`))
	createRec := httptest.NewRecorder()
	handler.ServeHTTP(createRec, createReq)
	if createRec.Code != http.StatusCreated {
		t.Fatalf("POST /networks/create status=%d body=%s", createRec.Code, createRec.Body.String())
	}
	var created map[string]interface{}
	if err := json.Unmarshal(createRec.Body.Bytes(), &created); err != nil {
		t.Fatalf("create response decode: %v", err)
	}
	netID, _ := created["Id"].(string)
	if netID == "" {
		t.Fatalf("create response missing Id: %s", createRec.Body.String())
	}

	connectReq := httptest.NewRequest(http.MethodPost, "/networks/"+netID+"/connect", bytes.NewBufferString(`{"Container":"abc123","EndpointConfig":{"Aliases":["svc"]}}`))
	connectRec := httptest.NewRecorder()
	handler.ServeHTTP(connectRec, connectReq)
	if connectRec.Code != http.StatusOK {
		t.Fatalf("POST /networks/{id}/connect status=%d body=%s", connectRec.Code, connectRec.Body.String())
	}

	inspectReq := httptest.NewRequest(http.MethodGet, "/networks/"+netID, nil)
	inspectRec := httptest.NewRecorder()
	handler.ServeHTTP(inspectRec, inspectReq)
	if inspectRec.Code != http.StatusOK {
		t.Fatalf("GET /networks/{id} status=%d body=%s", inspectRec.Code, inspectRec.Body.String())
	}
	var inspected map[string]interface{}
	if err := json.Unmarshal(inspectRec.Body.Bytes(), &inspected); err != nil {
		t.Fatalf("inspect response decode: %v", err)
	}
	containers, ok := inspected["Containers"].(map[string]interface{})
	if !ok || len(containers) == 0 {
		t.Fatalf("network inspect missing connected containers: %s", inspectRec.Body.String())
	}

	listReq := httptest.NewRequest(http.MethodGet, "/networks", nil)
	listRec := httptest.NewRecorder()
	handler.ServeHTTP(listRec, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /networks status=%d body=%s", listRec.Code, listRec.Body.String())
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
