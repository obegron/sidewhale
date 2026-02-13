package main

import "testing"

func TestNormalizeLayerPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
		ok   bool
	}{
		{in: "/bin/ryuk", want: "bin/ryuk", ok: true},
		{in: "usr/local/bin/tool", want: "usr/local/bin/tool", ok: true},
		{in: "../../etc/passwd", want: "", ok: false},
	}
	for _, tt := range tests {
		got, ok := normalizeLayerPath(tt.in)
		if got != tt.want || ok != tt.ok {
			t.Fatalf("normalizeLayerPath(%q) = (%q,%v), want (%q,%v)", tt.in, got, ok, tt.want, tt.ok)
		}
	}
}
