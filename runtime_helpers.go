package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func resolveUnixSocketPath(raw, stateDir string) string {
	val := strings.TrimSpace(raw)
	switch strings.ToLower(val) {
	case "-", "off", "none", "disabled":
		return ""
	case "":
		return filepath.Join(stateDir, "docker.sock")
	default:
		return val
	}
}

func listenUnixSocket(socketPath string) (net.Listener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode().Type() == fs.ModeSocket || info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			if rmErr := os.Remove(socketPath); rmErr != nil {
				return nil, rmErr
			}
		} else {
			return nil, fmt.Errorf("path exists and is not a socket: %s", socketPath)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, err
	}
	if chmodErr := os.Chmod(socketPath, 0o666); chmodErr != nil {
		ln.Close()
		return nil, chmodErr
	}
	return ln, nil
}

func timeoutMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeout := requestTimeoutFor(r)
		if timeout <= 0 {
			next.ServeHTTP(w, r)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestTimeoutFor(r *http.Request) time.Duration {
	path := r.URL.Path
	if rewritten, ok := rewriteVersionedPath(path); ok {
		path = rewritten
	}
	// Image pulls can take much longer than normal control-plane calls.
	if r.Method == http.MethodPost && path == "/images/create" {
		return 10 * time.Minute
	}
	// Rootfs clone for large images can also take longer than default.
	if r.Method == http.MethodPost && path == "/containers/create" {
		return 10 * time.Minute
	}
	// Docker clients may keep log follow streams open for long periods.
	if r.Method == http.MethodGet && strings.HasSuffix(path, "/logs") && parseDockerBool(r.URL.Query().Get("follow"), false) {
		return 0
	}
	// Wait endpoints are expected to block until exit.
	if r.Method == http.MethodPost && strings.HasSuffix(path, "/wait") {
		return 0
	}
	return 30 * time.Second
}

func requireUnprivilegedRuntime(euid int) error {
	if euid == 0 {
		return fmt.Errorf("refusing to run as root (uid 0)")
	}
	return nil
}

func buildContainerCommand(rootfs, tmpBind, workingDir, userSpec string, extraBinds []string, cmdArgs []string) (*exec.Cmd, error) {
	if len(cmdArgs) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	if err := ensureSyntheticUserIdentity(rootfs, userSpec); err != nil {
		return nil, err
	}
	prootPath, err := findProotPath()
	if err != nil {
		return nil, err
	}
	if workingDir == "" {
		workingDir = "/"
	}
	if strings.TrimSpace(tmpBind) == "" {
		tmpBind = "/tmp"
	}
	args := []string{
		"-r", rootfs,
		"-b", "/proc",
		"-b", "/dev",
		"-b", "/sys/fs/cgroup",
		"-b", tmpBind + ":/tmp",
		"-w", workingDir,
	}
	for _, bind := range extraBinds {
		bind = strings.TrimSpace(bind)
		if bind == "" {
			continue
		}
		args = append(args, "-b", bind)
	}
	if identity, ok := resolveProotIdentity(rootfs, userSpec); ok {
		args = append(args, "-i", identity)
	}
	if fileExists(filepath.Join(rootfs, "/usr/bin/env")) {
		args = append(args, "/usr/bin/env")
	} else if fileExists(filepath.Join(rootfs, "/bin/env")) {
		args = append(args, "/bin/env")
	}

	args = append(args, cmdArgs...)
	return exec.Command(prootPath, args...), nil
}

func findProotPath() (string, error) {
	if path, err := exec.LookPath("proot"); err == nil {
		return path, nil
	}
	if _, err := os.Stat("/proot"); err == nil {
		return "/proot", nil
	}
	return "", fmt.Errorf("missing proot binary (required for unprivileged image execution)")
}

func readMemTotal() int64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	return parseMemTotal(data)
}

func parseMemTotal(data []byte) int64 {
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				break
			}
			kb, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				break
			}
			return kb * 1024
		}
	}
	return 0
}
