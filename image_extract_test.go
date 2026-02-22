package main

import (
	"path/filepath"
	"testing"
)

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

func TestNormalizeSymlinkTargetAbsoluteInsideRootfs(t *testing.T) {
	rootfs := t.TempDir()
	symlinkPath := filepath.Join(rootfs, "bin", "sh")
	target, ok, err := normalizeSymlinkTarget("/bin/busybox", symlinkPath, rootfs)
	if err != nil || !ok {
		t.Fatalf("normalizeSymlinkTarget returned err=%v ok=%v", err, ok)
	}
	if target != "busybox" {
		t.Fatalf("normalizeSymlinkTarget target=%q, want %q", target, "busybox")
	}
}

func TestNormalizeSymlinkTargetRelativeEscapeRejected(t *testing.T) {
	rootfs := t.TempDir()
	symlinkPath := filepath.Join(rootfs, "usr", "bin", "tool")
	_, ok, err := normalizeSymlinkTarget("../../../etc/passwd", symlinkPath, rootfs)
	if err == nil || ok {
		t.Fatalf("expected unsafe symlink target to be rejected, got err=%v ok=%v", err, ok)
	}
}
