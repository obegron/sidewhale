package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleCreateK8sKeepsOriginalImageReference(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{},
		networks:   map[string]*Network{},
		execs:      map[string]*ExecInstance{},
		proxies:    map[string][]*portProxy{},
		stateDir:   t.TempDir(),
	}
	if err := store.init(); err != nil {
		t.Fatalf("store init: %v", err)
	}

	req := httptest.NewRequest(
		http.MethodPost,
		"/containers/create",
		strings.NewReader(`{"Image":"docker.io/library/alpine:3.17"}`),
	)
	rec := httptest.NewRecorder()
	handleCreate(
		rec,
		req,
		store,
		runtimeBackendK8s,
		nil,
		[]imageMirrorRule{{FromPrefix: "docker.io/", ToPrefix: "sidewhale-registry-cache.sidewhale-system.svc.cluster.local:5000/"}},
		"",
		false,
	)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d body=%s", rec.Code, http.StatusCreated, rec.Body.String())
	}
	id := strings.TrimSpace(parseJSONField(rec.Body.String(), "Id"))
	if id == "" {
		t.Fatalf("missing container id in response: %s", rec.Body.String())
	}
	c, ok := store.get(id)
	if !ok {
		t.Fatalf("container %q not found in store", id)
	}
	if c.ResolvedImage != "docker.io/library/alpine:3.17" {
		t.Fatalf("resolved image = %q, want original image reference", c.ResolvedImage)
	}
}

func parseJSONField(body string, key string) string {
	needle := `"` + key + `":"`
	idx := strings.Index(body, needle)
	if idx < 0 {
		return ""
	}
	rest := body[idx+len(needle):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

