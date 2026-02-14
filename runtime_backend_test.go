package main

import "testing"

func TestNormalizeRuntimeBackend(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{in: "", want: runtimeBackendHost},
		{in: "host", want: runtimeBackendHost},
		{in: "HOST", want: runtimeBackendHost},
		{in: "k8s", want: runtimeBackendK8s},
		{in: " K8S ", want: runtimeBackendK8s},
		{in: "podman", wantErr: true},
	}
	for _, tt := range tests {
		got, err := normalizeRuntimeBackend(tt.in)
		if tt.wantErr {
			if err == nil {
				t.Fatalf("normalizeRuntimeBackend(%q) expected error", tt.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("normalizeRuntimeBackend(%q) unexpected error: %v", tt.in, err)
		}
		if got != tt.want {
			t.Fatalf("normalizeRuntimeBackend(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
