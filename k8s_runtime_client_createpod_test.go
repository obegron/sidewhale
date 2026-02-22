package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreatePodLegacyCmdMappedToArgs(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := &k8sClient{
		baseURL:   srv.URL,
		token:     "x",
		namespace: "ns",
		http:      srv.Client(),
	}
	c := &Container{
		ID:            "abc123",
		Image:         "postgres:9.6.12",
		ResolvedImage: "postgres:9.6.12",
		Cmd:           []string{"postgres", "-c", "fsync=off"},
	}
	if _, err := client.createPod(context.Background(), c, nil); err != nil {
		t.Fatalf("createPod failed: %v", err)
	}

	spec := got["spec"].(map[string]interface{})
	containers := spec["containers"].([]interface{})
	container := containers[0].(map[string]interface{})
	if _, ok := container["command"]; ok {
		t.Fatalf("command should be unset for legacy cmd fallback payload: %#v", container["command"])
	}
	args, ok := container["args"].([]interface{})
	if !ok {
		t.Fatalf("args missing in payload: %#v", container)
	}
	if len(args) != 3 || args[0] != "postgres" || args[1] != "-c" || args[2] != "fsync=off" {
		t.Fatalf("args = %#v, want postgres -c fsync=off", args)
	}
}

func TestCreatePodEntrypointAndArgsMappedSeparately(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := &k8sClient{
		baseURL:   srv.URL,
		token:     "x",
		namespace: "ns",
		http:      srv.Client(),
	}
	c := &Container{
		ID:            "abc124",
		Image:         "alpine:3.17",
		ResolvedImage: "alpine:3.17",
		Entrypoint:    []string{"sh", "-c"},
		Args:          []string{"echo ok"},
	}
	if _, err := client.createPod(context.Background(), c, nil); err != nil {
		t.Fatalf("createPod failed: %v", err)
	}

	spec := got["spec"].(map[string]interface{})
	containers := spec["containers"].([]interface{})
	container := containers[0].(map[string]interface{})
	command := container["command"].([]interface{})
	args := container["args"].([]interface{})
	if len(command) != 2 || command[0] != "sh" || command[1] != "-c" {
		t.Fatalf("command = %#v, want [sh -c]", command)
	}
	if len(args) != 1 || args[0] != "echo ok" {
		t.Fatalf("args = %#v, want [echo ok]", args)
	}

	volumeMounts, ok := container["volumeMounts"].([]interface{})
	if !ok || len(volumeMounts) != 1 {
		t.Fatalf("volumeMounts = %#v, want one /dev/shm mount", container["volumeMounts"])
	}
	vm := volumeMounts[0].(map[string]interface{})
	if vm["name"] != "dshm" || vm["mountPath"] != "/dev/shm" {
		t.Fatalf("volumeMount = %#v, want {name:dshm mountPath:/dev/shm}", vm)
	}

	volumes, ok := spec["volumes"].([]interface{})
	if !ok || len(volumes) != 1 {
		t.Fatalf("volumes = %#v, want one dshm volume", spec["volumes"])
	}
	vol := volumes[0].(map[string]interface{})
	if vol["name"] != "dshm" {
		t.Fatalf("volume name = %#v, want dshm", vol["name"])
	}
	emptyDir, ok := vol["emptyDir"].(map[string]interface{})
	if !ok {
		t.Fatalf("emptyDir missing from volume: %#v", vol)
	}
	if emptyDir["medium"] != "Memory" || emptyDir["sizeLimit"] != "1Gi" {
		t.Fatalf("emptyDir = %#v, want medium=Memory sizeLimit=1Gi", emptyDir)
	}
}

func TestCreatePodTmpfsMappedToMemoryVolumes(t *testing.T) {
	var got map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	client := &k8sClient{
		baseURL:   srv.URL,
		token:     "x",
		namespace: "ns",
		http:      srv.Client(),
	}
	c := &Container{
		ID:            "tmpfs1",
		Image:         "postgres:16",
		ResolvedImage: "postgres:16",
		Tmpfs: map[string]string{
			"/testtmpfs": "rw,noexec,nosuid,size=65536k",
			"/readonly":  "ro,size=32m",
		},
	}
	if _, err := client.createPod(context.Background(), c, nil); err != nil {
		t.Fatalf("createPod failed: %v", err)
	}

	spec := got["spec"].(map[string]interface{})
	containers := spec["containers"].([]interface{})
	container := containers[0].(map[string]interface{})
	volumeMounts := container["volumeMounts"].([]interface{})

	foundTestTmpfs := false
	foundReadOnly := false
	for _, item := range volumeMounts {
		vm := item.(map[string]interface{})
		switch vm["mountPath"] {
		case "/testtmpfs":
			foundTestTmpfs = true
		case "/readonly":
			foundReadOnly = true
			if vm["readOnly"] != true {
				t.Fatalf("readonly tmpfs mount missing readOnly=true: %#v", vm)
			}
		}
	}
	if !foundTestTmpfs {
		t.Fatalf("missing /testtmpfs mount in volumeMounts: %#v", volumeMounts)
	}
	if !foundReadOnly {
		t.Fatalf("missing /readonly mount in volumeMounts: %#v", volumeMounts)
	}

	volumes := spec["volumes"].([]interface{})
	foundSized := false
	for _, item := range volumes {
		vol := item.(map[string]interface{})
		if !strings.HasPrefix(vol["name"].(string), "tmpfs-") {
			continue
		}
		emptyDir := vol["emptyDir"].(map[string]interface{})
		if emptyDir["medium"] != "Memory" {
			t.Fatalf("tmpfs emptyDir medium=%#v, want Memory", emptyDir["medium"])
		}
		if emptyDir["sizeLimit"] == "65536Ki" || emptyDir["sizeLimit"] == "32Mi" {
			foundSized = true
		}
	}
	if !foundSized {
		t.Fatalf("tmpfs volumes missing converted sizeLimit values: %#v", volumes)
	}
}
