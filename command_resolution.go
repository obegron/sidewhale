package main

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return process.Signal(syscall.Signal(0)) == nil
}

func resolveCommandInRootfs(rootfs string, env []string, cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return cmdArgs
	}
	adjusted := append([]string{}, cmdArgs...)
	if resolved, ok := resolveBinaryPathInRootfs(rootfs, env, adjusted[0]); ok {
		adjusted[0] = resolved
	}
	adjusted = rewriteShebangCommand(rootfs, env, adjusted)
	return rewriteKnownEntrypointCompat(adjusted)
}

func rewriteKnownEntrypointCompat(cmdArgs []string) []string {
	if len(cmdArgs) >= 3 && strings.HasSuffix(cmdArgs[0], "/bash") && strings.HasSuffix(cmdArgs[1], "/opt/mssql/bin/launch_sqlservr.sh") {
		return append([]string{cmdArgs[2]}, cmdArgs[3:]...)
	}
	if len(cmdArgs) >= 2 && strings.HasSuffix(cmdArgs[0], "/opt/mssql/bin/launch_sqlservr.sh") {
		return append([]string{cmdArgs[1]}, cmdArgs[2:]...)
	}
	return cmdArgs
}

func resolveBinaryPathInRootfs(rootfs string, env []string, cmd string) (string, bool) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", false
	}

	if strings.HasPrefix(cmd, "/") {
		joined := filepath.Join(rootfs, strings.TrimPrefix(cmd, "/"))
		if fileExists(joined) {
			return cmd, true
		}
	}

	pathVal := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	for _, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			pathVal = strings.TrimPrefix(e, "PATH=")
			break
		}
	}
	base := filepath.Base(cmd)
	searchDirs := strings.Split(pathVal, ":")
	searchDirs = append(searchDirs, "/app", "/")
	for _, dir := range searchDirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		candidate := filepath.Join(rootfs, strings.TrimPrefix(dir, "/"), base)
		if fileExists(candidate) {
			return filepath.Join(dir, base), true
		}
	}

	if found, ok := findExecutableByBase(rootfs, base); ok {
		return found, true
	}

	return "", false
}

func rewriteShebangCommand(rootfs string, env []string, cmdArgs []string) []string {
	if len(cmdArgs) == 0 {
		return cmdArgs
	}
	if !strings.HasPrefix(cmdArgs[0], "/") {
		return cmdArgs
	}

	scriptPath := filepath.Join(rootfs, strings.TrimPrefix(cmdArgs[0], "/"))
	line, err := readFirstLine(scriptPath)
	if err != nil || !strings.HasPrefix(line, "#!") {
		return cmdArgs
	}

	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(line, "#!")))
	if len(fields) == 0 {
		return cmdArgs
	}

	interpreter := fields[0]
	interpArgs := fields[1:]
	if interpreter == "/usr/bin/env" || interpreter == "/bin/env" {
		if len(interpArgs) == 0 {
			return cmdArgs
		}
		interpreter = interpArgs[0]
		interpArgs = interpArgs[1:]
	}

	resolvedInterp, ok := resolveBinaryPathInRootfs(rootfs, env, interpreter)
	if !ok {
		return cmdArgs
	}

	rewritten := []string{resolvedInterp}
	rewritten = append(rewritten, interpArgs...)
	rewritten = append(rewritten, cmdArgs...)
	return rewritten
}

func readFirstLine(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if n == 0 {
		return "", io.EOF
	}
	line := string(buf[:n])
	if idx := strings.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	return strings.TrimSuffix(line, "\r"), nil
}

func fileExists(path string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	return info.Mode().IsRegular()
}

func findExecutableByBase(rootfs string, base string) (string, bool) {
	if strings.TrimSpace(base) == "" {
		return "", false
	}
	var found string
	const maxEntries = 50000
	seen := 0
	_ = filepath.WalkDir(rootfs, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if seen >= maxEntries {
			return fs.SkipAll
		}
		seen++
		if d.IsDir() {
			return nil
		}
		if filepath.Base(p) != base {
			return nil
		}
		rel, relErr := filepath.Rel(rootfs, p)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if rel == "." || strings.HasPrefix(rel, "../") {
			return nil
		}
		found = "/" + rel
		return fs.SkipAll
	})
	return found, found != ""
}

func firstArg(cmd []string) string {
	if len(cmd) == 0 {
		return ""
	}
	return cmd[0]
}

func restArgs(cmd []string) []string {
	if len(cmd) <= 1 {
		return nil
	}
	return cmd[1:]
}

func statusFromRunning(running bool) string {
	if running {
		return "running"
	}
	return "exited"
}
