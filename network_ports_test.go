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
