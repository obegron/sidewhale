package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"
)

var shellNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func handleExecCreate(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	var req execCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil && err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if len(req.Cmd) == 0 {
		writeError(w, http.StatusBadRequest, "missing exec command")
		return
	}
	execID, err := randomID(12)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "id generation failed")
		return
	}
	inst := &ExecInstance{
		ID:          execID,
		ContainerID: c.ID,
		Cmd:         append([]string{}, req.Cmd...),
		User:        strings.TrimSpace(req.User),
		WorkingDir:  strings.TrimSpace(req.WorkingDir),
		Env:         append([]string{}, req.Env...),
		ExitCode:    -1,
	}
	store.putExec(inst)
	writeJSON(w, http.StatusCreated, execCreateResponse{ID: execID})
}

func handleExecStart(w http.ResponseWriter, r *http.Request, store *containerStore, execID string) {
	inst, ok := store.findExec(execID)
	if !ok {
		writeError(w, http.StatusNotFound, "exec instance not found")
		return
	}
	c, ok := store.findContainer(inst.ContainerID)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	inst.Running = true
	store.putExec(inst)
	runErr := error(nil)
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err != nil {
			runErr = err
		} else {
			k8sCmd := buildK8sExecCommand(c, inst)
			out, errOut, code, err := client.execPod(r.Context(), c.K8sNamespace, c.K8sPodName, k8sCmd)
			stdoutBuf.Write(out)
			stderrBuf.Write(errOut)
			inst.ExitCode = code
			runErr = err
			if err != nil {
				log.Printf("sidewhale: k8s exec failed pod=%s/%s cmd=%q err=%v", c.K8sNamespace, c.K8sPodName, k8sCmd, err)
			}
			if err == nil && code == 0 {
				runErr = nil
			}
		}
	} else {
		execEnv := mergeEnv(c.Env, inst.Env)
		execUser := firstNonEmpty(strings.TrimSpace(inst.User), strings.TrimSpace(c.User))
		execWorkingDir := firstNonEmpty(strings.TrimSpace(inst.WorkingDir), strings.TrimSpace(c.WorkingDir))
		cmdArgs := resolveCommandInRootfs(c.Rootfs, execEnv, inst.Cmd)
		socketBinds, err := dockerSocketBindsForContainer(c, unixSocketPathFromContainerEnv(execEnv))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "exec start failed: "+err.Error())
			return
		}
		cmd, err := buildContainerCommand(c.Rootfs, containerTmpDir(c), execWorkingDir, execUser, socketBinds, cmdArgs)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "exec start failed: "+err.Error())
			return
		}
		cmd.Dir = "/"
		cmd.Env = deduplicateEnv(append(os.Environ(), execEnv...))
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stdout = &stdoutBuf
		cmd.Stderr = &stderrBuf
		runErr = cmd.Run()
	}
	inst.Running = false
	if runErr != nil && inst.ExitCode <= 0 {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			inst.ExitCode = exitErr.ExitCode()
		} else {
			inst.ExitCode = 126
		}
	} else if inst.ExitCode < 0 {
		inst.ExitCode = 0
	}
	inst.Stdout = append([]byte(nil), stdoutBuf.Bytes()...)
	inst.Stderr = append([]byte(nil), stderrBuf.Bytes()...)
	inst.Output = append(append([]byte(nil), inst.Stdout...), inst.Stderr...)
	store.putExec(inst)

	connHdr := strings.ToLower(r.Header.Get("Connection"))
	if strings.Contains(connHdr, "upgrade") {
		hj, ok := w.(http.Hijacker)
		if !ok {
			writeError(w, http.StatusInternalServerError, "hijack not supported")
			return
		}
		conn, rw, err := hj.Hijack()
		if err != nil {
			return
		}
		defer closeHijackedConn(conn)
		writeExecUpgradeResponse(rw, inst.Stdout, inst.Stderr)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.docker.raw-stream")
	w.WriteHeader(http.StatusOK)
	if len(inst.Stdout) > 0 {
		_, _ = w.Write(frameDockerRawStream(1, inst.Stdout))
	}
	if len(inst.Stderr) > 0 {
		_, _ = w.Write(frameDockerRawStream(2, inst.Stderr))
	}
}

func writeExecUpgradeResponse(rw *bufio.ReadWriter, stdout, stderr []byte) {
	_, _ = rw.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	_, _ = rw.WriteString("Connection: Upgrade\r\n")
	_, _ = rw.WriteString("Upgrade: tcp\r\n")
	_, _ = rw.WriteString("Content-Type: application/vnd.docker.raw-stream\r\n")
	_, _ = rw.WriteString("\r\n")
	if len(stdout) > 0 {
		_, _ = rw.Write(frameDockerRawStream(1, stdout))
	}
	if len(stderr) > 0 {
		_, _ = rw.Write(frameDockerRawStream(2, stderr))
	}
	_ = rw.Flush()
}

func closeHijackedConn(conn net.Conn) {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return
	}
	_ = tcp.CloseWrite()
	_ = tcp.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
	_, _ = io.Copy(io.Discard, tcp)
	_ = tcp.Close()
}

func buildK8sExecCommand(c *Container, inst *ExecInstance) []string {
	user := strings.TrimSpace(inst.User)
	wd := firstNonEmpty(strings.TrimSpace(inst.WorkingDir), strings.TrimSpace(c.WorkingDir))
	if user == "" && wd == "" && len(inst.Env) == 0 {
		return append([]string{}, inst.Cmd...)
	}
	script := shellJoin(inst.Cmd)
	if wd != "" {
		script = "cd " + shellQuote(wd) + " && " + script
	}
	assignments := make([]string, 0, len(inst.Env))
	for _, raw := range inst.Env {
		key, value := splitEnv(raw)
		if !shellNamePattern.MatchString(key) {
			continue
		}
		assignments = append(assignments, fmt.Sprintf("%s=%s", key, shellQuote(value)))
	}
	if len(assignments) > 0 {
		script = "export " + strings.Join(assignments, " ") + "; " + script
	}
	if user == "" {
		return []string{"sh", "-lc", script}
	}
	return []string{"sh", "-lc", "exec su -s /bin/sh -c " + shellQuote(script) + " " + shellQuote(user)}
}

func shellJoin(args []string) string {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func handleExecJSON(w http.ResponseWriter, r *http.Request, store *containerStore, execID string) {
	inst, ok := store.findExec(execID)
	if !ok {
		writeError(w, http.StatusNotFound, "exec instance not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"ID":       inst.ID,
		"Running":  inst.Running,
		"ExitCode": inst.ExitCode,
		"ProcessConfig": map[string]interface{}{
			"entrypoint": firstArg(inst.Cmd),
			"arguments":  restArgs(inst.Cmd),
		},
	})
}
