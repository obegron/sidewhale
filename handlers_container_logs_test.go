package main

import (
	"encoding/binary"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHandleLogsFiltersStderr(t *testing.T) {
	stateDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(stateDir, "containers"), 0o755); err != nil {
		t.Fatalf("mkdir containers: %v", err)
	}
	stdoutPath := filepath.Join(stateDir, "stdout.log")
	stderrPath := filepath.Join(stateDir, "stderr.log")
	if err := os.WriteFile(stdoutPath, []byte("stdout\n"), 0o644); err != nil {
		t.Fatalf("write stdout: %v", err)
	}
	if err := os.WriteFile(stderrPath, []byte("stderr\n"), 0o644); err != nil {
		t.Fatalf("write stderr: %v", err)
	}
	store := &containerStore{
		containers: map[string]*Container{
			"abc123": {
				ID:         "abc123",
				Created:    time.Now().UTC(),
				LogPath:    stdoutPath,
				StdoutPath: stdoutPath,
				StderrPath: stderrPath,
			},
		},
		stateDir: stateDir,
		proxies:  make(map[string][]*portProxy),
		execs:    make(map[string]*ExecInstance),
	}

	req := httptest.NewRequest(http.MethodGet, "/containers/abc123/logs?stdout=false&stderr=true", nil)
	rr := httptest.NewRecorder()
	handleLogs(rr, req, store, "abc123")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	frames := decodeRawFrames(t, rr.Body.Bytes())
	if len(frames) != 1 {
		t.Fatalf("frame count = %d, want 1", len(frames))
	}
	if frames[0].stream != 2 {
		t.Fatalf("stream = %d, want 2", frames[0].stream)
	}
	if string(frames[0].payload) != "stderr\n" {
		t.Fatalf("payload = %q, want %q", frames[0].payload, "stderr\n")
	}
}

type rawFrame struct {
	stream  byte
	payload []byte
}

func decodeRawFrames(t *testing.T, raw []byte) []rawFrame {
	t.Helper()
	out := make([]rawFrame, 0)
	for len(raw) > 0 {
		if len(raw) < 8 {
			t.Fatalf("short frame header length: %d", len(raw))
		}
		size := int(binary.BigEndian.Uint32(raw[4:8]))
		if len(raw) < 8+size {
			t.Fatalf("short frame payload: have %d need %d", len(raw), 8+size)
		}
		payload := make([]byte, size)
		copy(payload, raw[8:8+size])
		out = append(out, rawFrame{
			stream:  raw[0],
			payload: payload,
		})
		raw = raw[8+size:]
	}
	return out
}
