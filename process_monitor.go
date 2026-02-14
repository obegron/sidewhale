package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func monitorContainer(id string, pid int, logPath string, store *containerStore, limits runtimeLimits) {
	if pid <= 0 {
		return
	}
	c, ok := store.get(id)
	checkOracleFatal := ok && isOracleImage(c.Image)
	containerDir := ""
	if ok {
		containerDir = filepath.Dir(c.Rootfs)
	}
	if limits.maxRuntime <= 0 && limits.maxLogBytes <= 0 && limits.maxMemBytes <= 0 && limits.maxDiskBytes <= 0 && !checkOracleFatal {
		return
	}
	deadline := time.Now().Add(limits.maxRuntime)
	var scannedOffset int64
	var scannedCarry string
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		if !processAlive(pid) {
			return
		}
		if limits.maxRuntime > 0 && time.Now().After(deadline) {
			fmt.Printf("sidewhale: monitor killed container id=%s pid=%d reason=max_runtime limit=%s\n", id, pid, limits.maxRuntime)
			_ = killProcessGroup(pid, syscall.SIGKILL)
			exitCode := 137
			store.markStoppedWithExit(id, &exitCode, time.Now().UTC())
			return
		}
		if limits.maxLogBytes > 0 {
			if info, err := os.Stat(logPath); err == nil && info.Size() > limits.maxLogBytes {
				fmt.Printf("sidewhale: monitor killed container id=%s pid=%d reason=max_log_bytes size=%d limit=%d\n", id, pid, info.Size(), limits.maxLogBytes)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				exitCode := 137
				store.markStoppedWithExit(id, &exitCode, time.Now().UTC())
				return
			}
		}
		if limits.maxMemBytes > 0 {
			if rss, err := readRSS(pid); err == nil && rss > limits.maxMemBytes {
				fmt.Printf("sidewhale: monitor killed container id=%s pid=%d reason=max_mem_bytes rss=%d limit=%d\n", id, pid, rss, limits.maxMemBytes)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				exitCode := 137
				store.markStoppedWithExit(id, &exitCode, time.Now().UTC())
				return
			}
		}
		if limits.maxDiskBytes > 0 && containerDir != "" {
			if size, err := dirSize(containerDir); err == nil && size > limits.maxDiskBytes {
				fmt.Printf("sidewhale: monitor killed container id=%s pid=%d reason=max_disk_bytes size=%d limit=%d\n", id, pid, size, limits.maxDiskBytes)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				exitCode := 137
				store.markStoppedWithExit(id, &exitCode, time.Now().UTC())
				return
			}
		}
		if checkOracleFatal {
			matched, sig, nextOffset, nextCarry := scanFatalLogSignatures(logPath, scannedOffset, scannedCarry, oracleFatalLogSignatures)
			scannedOffset = nextOffset
			scannedCarry = nextCarry
			if matched {
				fmt.Printf("sidewhale: monitor killed container id=%s pid=%d reason=fatal_log signature=%q\n", id, pid, sig)
				_ = killProcessGroup(pid, syscall.SIGKILL)
				exitCode := 137
				store.markStoppedWithExit(id, &exitCode, time.Now().UTC())
				return
			}
		}
	}
}

var oracleFatalLogSignatures = []string{
	"ora-27300: os system dependent operation:pr_set_dumpable failed",
	"ora-27301: os failure message: function not implemented",
	"ora-27302: failure occurred at: sskgp_mod_fd",
	"sp2-0157: unable to connect to oracle",
}

func scanFatalLogSignatures(logPath string, offset int64, carry string, signatures []string) (bool, string, int64, string) {
	info, err := os.Stat(logPath)
	if err != nil {
		return false, "", offset, carry
	}
	if info.Size() < offset {
		offset = 0
		carry = ""
	}
	if info.Size() == offset {
		return false, "", offset, carry
	}

	f, err := os.Open(logPath)
	if err != nil {
		return false, "", offset, carry
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return false, "", offset, carry
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return false, "", offset, carry
	}
	offset += int64(len(data))

	text := strings.ToLower(carry + string(data))
	for _, sig := range signatures {
		if strings.Contains(text, sig) {
			return true, sig, offset, carry
		}
	}

	const maxCarry = 4096
	if len(text) > maxCarry {
		carry = text[len(text)-maxCarry:]
	} else {
		carry = text
	}
	return false, "", offset, carry
}

func terminateProcessTree(pid int, grace time.Duration) {
	if pid <= 0 {
		return
	}
	_ = killProcessGroup(pid, syscall.SIGTERM)
	if grace <= 0 {
		_ = killProcessGroup(pid, syscall.SIGKILL)
		return
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = killProcessGroup(pid, syscall.SIGKILL)
}

func killProcessGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return nil
	}
	return syscall.Kill(-pid, sig)
}

func readRSS(pid int) (int64, error) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "VmRSS:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, err := strconv.ParseInt(fields[1], 10, 64)
				if err != nil {
					return 0, err
				}
				return val * 1024, nil
			}
		}
	}
	return 0, fmt.Errorf("VmRSS not found")
}
