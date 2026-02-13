package main

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"
)

func TestToDockerPortSummaries(t *testing.T) {
	got := toDockerPortSummaries(map[int]int{5432: 32780})
	if len(got) != 1 {
		t.Fatalf("expected one port summary, got %d", len(got))
	}
	entry := got[0]
	if entry["PrivatePort"] != 5432 || entry["PublicPort"] != 32780 || entry["Type"] != "tcp" {
		t.Fatalf("unexpected port summary: %#v", entry)
	}
}

func TestFrameDockerRawStream(t *testing.T) {
	payload := []byte("hej\n")
	framed := frameDockerRawStream(1, payload)
	if len(framed) != 8+len(payload) {
		t.Fatalf("framed length = %d, want %d", len(framed), 8+len(payload))
	}
	if framed[0] != 1 {
		t.Fatalf("stream byte = %d, want 1", framed[0])
	}
	size := binary.BigEndian.Uint32(framed[4:8])
	if int(size) != len(payload) {
		t.Fatalf("size header = %d, want %d", size, len(payload))
	}
	if string(framed[8:]) != string(payload) {
		t.Fatalf("payload = %q, want %q", framed[8:], payload)
	}
}

func TestIsTCPPortInUse(t *testing.T) {
	port, err := allocatePort()
	if err != nil {
		t.Fatalf("allocatePort error: %v", err)
	}
	if isTCPPortInUse(port) {
		t.Fatalf("expected free port %d to be available", port)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatalf("listen on test port: %v", err)
	}
	defer ln.Close()
	if !isTCPPortInUse(port) {
		t.Fatalf("expected occupied port %d to be reported in use", port)
	}
}

func TestParsePort(t *testing.T) {
	tests := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{in: "5432/tcp", want: 5432},
		{in: "8080", want: 8080},
		{in: " 6379/tcp ", want: 6379},
		{in: "abc", wantErr: true},
	}
	for _, tt := range tests {
		got, err := parsePort(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("parsePort(%q) expected error, got nil", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parsePort(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("parsePort(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestResolvePortBindingsHonorsExplicitHostPort(t *testing.T) {
	exposed := map[string]struct{}{
		"5432/tcp": {},
	}
	hostBindings := map[string][]portBinding{
		"5432/tcp": {
			{HostPort: "15432"},
		},
	}
	got, err := resolvePortBindings(exposed, hostBindings)
	if err != nil {
		t.Fatalf("resolvePortBindings error: %v", err)
	}
	if got[5432] != 15432 {
		t.Fatalf("resolvePortBindings host port = %d, want 15432", got[5432])
	}
}

func TestResolvePortBindingsAllocatesWhenHostPortMissing(t *testing.T) {
	exposed := map[string]struct{}{
		"6379/tcp": {},
	}
	got, err := resolvePortBindings(exposed, nil)
	if err != nil {
		t.Fatalf("resolvePortBindings error: %v", err)
	}
	if got[6379] == 0 {
		t.Fatalf("expected allocated host port for 6379, got 0")
	}
}

func TestResolvePortBindingsRejectsInvalidHostPort(t *testing.T) {
	exposed := map[string]struct{}{
		"5432/tcp": {},
	}
	hostBindings := map[string][]portBinding{
		"5432/tcp": {
			{HostPort: "not-a-port"},
		},
	}
	_, err := resolvePortBindings(exposed, hostBindings)
	if err == nil {
		t.Fatalf("expected invalid host port error, got nil")
	}
}
