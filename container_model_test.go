package main

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestContainerLookupByNameAndShortID(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"f1513654ce811a41bfe0292e": {
				ID:      "f1513654ce811a41bfe0292e",
				Name:    "t1",
				Image:   "alpine:3.20",
				Created: time.Now().UTC(),
			},
		},
	}

	if c, ok := store.findContainer("t1"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by name failed: ok=%v c=%+v", ok, c)
	}
	if c, ok := store.findContainer("/t1"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by slash-name failed: ok=%v c=%+v", ok, c)
	}
	if c, ok := store.findContainer("f1513654"); !ok || c.ID != "f1513654ce811a41bfe0292e" {
		t.Fatalf("lookup by short id failed: ok=%v c=%+v", ok, c)
	}
}

func TestContainerDisplayName(t *testing.T) {
	withName := &Container{ID: "abc", Name: "db"}
	if got := containerDisplayName(withName); got != "/db" {
		t.Fatalf("containerDisplayName(withName) = %q, want %q", got, "/db")
	}
	withoutName := &Container{ID: "abc"}
	if got := containerDisplayName(withoutName); got != "/abc" {
		t.Fatalf("containerDisplayName(withoutName) = %q, want %q", got, "/abc")
	}
}

func TestListContainersIncludesCommand(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Image:   "alpine:3.20",
				Cmd:     []string{"echo", "hej"},
				Created: time.Now().UTC(),
			},
		},
	}
	list := store.listContainers()
	if len(list) != 1 {
		t.Fatalf("expected one container, got %d", len(list))
	}
	if list[0]["Command"] != "echo hej" {
		t.Fatalf("unexpected command field: %#v", list[0]["Command"])
	}
}

func TestNormalizeContainerHostname(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "", want: ""},
		{in: " db_1 ", want: "db-1"},
		{in: "alpha.beta", want: "alpha.beta"},
		{in: "!!!", want: ""},
	}
	for _, tt := range tests {
		if got := normalizeContainerHostname(tt.in); got != tt.want {
			t.Fatalf("normalizeContainerHostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestWriteContainerIdentityFiles(t *testing.T) {
	rootfs := t.TempDir()
	if err := writeContainerIdentityFiles(rootfs, "tc-host"); err != nil {
		t.Fatalf("writeContainerIdentityFiles error: %v", err)
	}
	hostnameData, err := os.ReadFile(filepath.Join(rootfs, "etc", "hostname"))
	if err != nil {
		t.Fatalf("read hostname: %v", err)
	}
	if string(hostnameData) != "tc-host\n" {
		t.Fatalf("hostname content = %q, want %q", string(hostnameData), "tc-host\n")
	}
	hostsData, err := os.ReadFile(filepath.Join(rootfs, "etc", "hosts"))
	if err != nil {
		t.Fatalf("read hosts: %v", err)
	}
	hosts := string(hostsData)
	if !strings.Contains(hosts, "127.0.1.1\ttc-host") {
		t.Fatalf("hosts missing hostname mapping: %q", hosts)
	}
	if err := writeContainerIdentityFiles(rootfs, "tc-host"); err != nil {
		t.Fatalf("writeContainerIdentityFiles second call error: %v", err)
	}
	hostsData2, err := os.ReadFile(filepath.Join(rootfs, "etc", "hosts"))
	if err != nil {
		t.Fatalf("read hosts after second call: %v", err)
	}
	if strings.Count(string(hostsData2), "tc-host") != 1 {
		t.Fatalf("expected single hostname entry, got: %q", string(hostsData2))
	}
}

func TestHandleJSONIncludesPausedState(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:      "abc123",
				Name:    "test-db",
				Image:   "alpine:3.20",
				Cmd:     []string{"echo", "hej"},
				Created: time.Now().UTC(),
				Ports:   map[int]int{5432: 32768},
			},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.local", nil)
	handleJSON(rr, req, store, "abc123")
	body := rr.Body.String()
	if !strings.Contains(body, "\"Paused\":false") {
		t.Fatalf("inspect response missing Paused=false: %s", body)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("inspect payload invalid json: %v", err)
	}
	if payload["Name"] != "/test-db" {
		t.Fatalf("inspect response Name = %#v, want /test-db", payload["Name"])
	}
	if _, ok := payload["HostConfig"]; !ok {
		t.Fatalf("inspect response missing HostConfig: %s", body)
	}
	config, ok := payload["Config"].(map[string]interface{})
	if !ok {
		t.Fatalf("inspect response Config missing or wrong type: %s", body)
	}
	if _, ok := config["ExposedPorts"]; !ok {
		t.Fatalf("inspect response missing Config.ExposedPorts: %s", body)
	}
}

func TestHandleJSONKeepsAllExposedPortsWhenOnlySubsetPublished(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID: "abc123",
				ExposedPorts: map[string]struct{}{
					"8080/tcp": {},
					"8081/tcp": {},
				},
				Ports: map[int]int{
					8080: 32768,
				},
				Created: time.Now().UTC(),
			},
		},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.local", nil)
	handleJSON(rr, req, store, "abc123")
	var payload map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("inspect payload invalid json: %v", err)
	}
	config, ok := payload["Config"].(map[string]interface{})
	if !ok {
		t.Fatalf("inspect response Config missing or wrong type: %s", rr.Body.String())
	}
	exposed, ok := config["ExposedPorts"].(map[string]interface{})
	if !ok {
		t.Fatalf("Config.ExposedPorts missing or wrong type: %s", rr.Body.String())
	}
	if _, ok := exposed["8080/tcp"]; !ok {
		t.Fatalf("missing exposed 8080/tcp: %s", rr.Body.String())
	}
	if _, ok := exposed["8081/tcp"]; !ok {
		t.Fatalf("missing exposed 8081/tcp: %s", rr.Body.String())
	}
	hostConfig, ok := payload["HostConfig"].(map[string]interface{})
	if !ok {
		t.Fatalf("inspect response HostConfig missing or wrong type: %s", rr.Body.String())
	}
	portBindings, ok := hostConfig["PortBindings"].(map[string]interface{})
	if !ok {
		t.Fatalf("HostConfig.PortBindings missing or wrong type: %s", rr.Body.String())
	}
	if _, ok := portBindings["8080/tcp"]; !ok {
		t.Fatalf("missing published 8080/tcp binding: %s", rr.Body.String())
	}
	if _, ok := portBindings["8081/tcp"]; ok {
		t.Fatalf("unexpected published 8081/tcp binding: %s", rr.Body.String())
	}
}

func TestContainerRuntimeImage(t *testing.T) {
	c := &Container{Image: "img:1", ResolvedImage: "mirror/img:1"}
	if got := containerRuntimeImage(c); got != "mirror/img:1" {
		t.Fatalf("containerRuntimeImage resolved = %q, want %q", got, "mirror/img:1")
	}
	c.ResolvedImage = ""
	if got := containerRuntimeImage(c); got != "img:1" {
		t.Fatalf("containerRuntimeImage fallback = %q, want %q", got, "img:1")
	}
}

func TestContainerEntrypointAndArgsLegacyFallback(t *testing.T) {
	c := &Container{
		Cmd: []string{"postgres", "-c", "fsync=off"},
	}
	entrypoint, args := containerEntrypointAndArgs(c)
	if len(entrypoint) != 0 {
		t.Fatalf("entrypoint = %v, want empty", entrypoint)
	}
	if len(args) != 3 || args[0] != "postgres" || args[1] != "-c" || args[2] != "fsync=off" {
		t.Fatalf("args = %v, want [postgres -c fsync=off]", args)
	}
}

func TestMergeContainerHostAliases(t *testing.T) {
	base := map[string]string{"db": "127.0.0.2"}
	got := mergeContainerHostAliases(base, []string{"db:127.0.0.9", "cache=127.0.0.3", "bad"})
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	if got["db"] != "127.0.0.9" {
		t.Fatalf("db ip = %q, want %q", got["db"], "127.0.0.9")
	}
	if got["cache"] != "127.0.0.3" {
		t.Fatalf("cache ip = %q, want %q", got["cache"], "127.0.0.3")
	}
}

func TestBuildK8sHostAliasesSorted(t *testing.T) {
	in := map[string]string{
		"B_db":    "10.0.0.2",
		"cache_1": "10.0.0.3",
		"a-db":    "10.0.0.2",
	}
	aliases := buildK8sHostAliases(in)
	if len(aliases) != 2 {
		t.Fatalf("len(aliases) = %d, want 2 (%v)", len(aliases), aliases)
	}
	first := aliases[0]
	if first["ip"] != "10.0.0.2" {
		t.Fatalf("first ip = %#v, want 10.0.0.2", first["ip"])
	}
	firstHosts, ok := first["hostnames"].([]string)
	if !ok || len(firstHosts) != 2 {
		t.Fatalf("first hostnames = %#v, want two names", first["hostnames"])
	}
	if firstHosts[0] != "a-db" || firstHosts[1] != "b-db" {
		t.Fatalf("first hostnames = %v, want [a-db b-db]", firstHosts)
	}
}

func TestKafkaListenerHostAliases(t *testing.T) {
	c := &Container{
		Image: "apache/kafka-native:3.8.0",
		Env: []string{
			"KAFKA_LISTENERS=PLAINTEXT://0.0.0.0:9092,BROKER://localhost:9093,TC-0://kafka:19092",
		},
	}
	got := kafkaListenerHostAliases(c)
	if len(got) != 1 {
		t.Fatalf("len(got) = %d, want 1 (%v)", len(got), got)
	}
	if got["kafka"] != "127.0.0.1" {
		t.Fatalf("kafka ip = %q, want 127.0.0.1", got["kafka"])
	}
}
