package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	k8sRuntimeContainerName = "workload"
)

type k8sClient struct {
	baseURL          string
	token            string
	namespace        string
	imagePullSecrets []string
	http             *http.Client
}

type k8sPod struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Status struct {
		Phase             string               `json:"phase"`
		PodIP             string               `json:"podIP"`
		ContainerStatuses []k8sContainerStatus `json:"containerStatuses"`
	} `json:"status"`
}

type k8sContainerStatus struct {
	Name  string `json:"name"`
	State struct {
		Running *struct {
			StartedAt string `json:"startedAt"`
		} `json:"running,omitempty"`
		Waiting *struct {
			Reason string `json:"reason"`
		} `json:"waiting,omitempty"`
		Terminated *struct {
			ExitCode   int    `json:"exitCode"`
			Reason     string `json:"reason"`
			StartedAt  string `json:"startedAt"`
			FinishedAt string `json:"finishedAt"`
		} `json:"terminated,omitempty"`
	} `json:"state"`
}

type k8sPodRuntimeState struct {
	Running    bool
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
}

type k8sPodList struct {
	Items []k8sPod `json:"items"`
}

func newInClusterK8sClient() (*k8sClient, error) {
	host := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_HOST"))
	if host == "" {
		return nil, fmt.Errorf("k8s service host not set")
	}
	port := strings.TrimSpace(os.Getenv("KUBERNETES_SERVICE_PORT"))
	if port == "" {
		port = "443"
	}
	baseURL := "https://" + host + ":" + port

	ns := strings.TrimSpace(os.Getenv("POD_NAMESPACE"))
	if ns == "" {
		ns = strings.TrimSpace(os.Getenv("K8S_NAMESPACE"))
	}
	if ns == "" {
		ns = "default"
	}

	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	tokenBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount token: %w", err)
	}
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount ca: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, fmt.Errorf("failed to parse serviceaccount CA")
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
	}
	return &k8sClient{
		baseURL:   baseURL,
		token:     strings.TrimSpace(string(tokenBytes)),
		namespace: ns,
		http: &http.Client{
			Timeout:   30 * time.Second,
			Transport: tr,
		},
	}, nil
}

func (k *k8sClient) createPod(ctx context.Context, c *Container, hostAliasMap map[string]string) (string, error) {
	image := strings.TrimSpace(c.ResolvedImage)
	if image == "" {
		image = strings.TrimSpace(c.Image)
	}
	if image == "" {
		return "", fmt.Errorf("missing image")
	}
	podName := "sidewhale-" + c.ID
	entrypoint := append([]string{}, c.Entrypoint...)
	args := append([]string{}, c.Args...)
	if len(entrypoint) == 0 && len(args) == 0 {
		// Backward compatibility for containers created before Entrypoint/Args
		// fields existed. Prefer preserving image ENTRYPOINT semantics by
		// treating legacy Cmd as args.
		args = append([]string{}, c.Cmd...)
	}
	env := make([]map[string]string, 0, len(c.Env))
	for _, item := range c.Env {
		key, val, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		env = append(env, map[string]string{
			"name":  key,
			"value": val,
		})
	}
	containerSpec := map[string]interface{}{
		"name":            k8sRuntimeContainerName,
		"image":           image,
		"imagePullPolicy": "IfNotPresent",
		"env":             env,
	}
	if len(entrypoint) > 0 {
		containerSpec["command"] = entrypoint
	}
	if len(args) > 0 {
		containerSpec["args"] = args
	}
	if wd := strings.TrimSpace(c.WorkingDir); wd != "" {
		containerSpec["workingDir"] = wd
	}
	pod := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      podName,
			"namespace": k.namespace,
			"labels": map[string]string{
				"app.kubernetes.io/name": "sidewhale-workload",
				"sidewhale.container-id": c.ID,
				"sidewhale.managed":      "true",
			},
		},
		"spec": map[string]interface{}{
			"restartPolicy": "Never",
			"containers":    []map[string]interface{}{containerSpec},
		},
	}
	if len(hostAliasMap) > 0 {
		grouped := map[string][]string{}
		for host, ip := range hostAliasMap {
			host = strings.ToLower(normalizeContainerHostname(host))
			ip = strings.TrimSpace(ip)
			if host == "" || ip == "" {
				continue
			}
			grouped[ip] = append(grouped[ip], host)
		}
		if len(grouped) > 0 {
			ips := make([]string, 0, len(grouped))
			for ip := range grouped {
				ips = append(ips, ip)
			}
			sort.Strings(ips)
			hostAliases := make([]map[string]interface{}, 0, len(ips))
			for _, ip := range ips {
				names := grouped[ip]
				sort.Strings(names)
				hostAliases = append(hostAliases, map[string]interface{}{
					"ip":        ip,
					"hostnames": names,
				})
			}
			podSpec := pod["spec"].(map[string]interface{})
			podSpec["hostAliases"] = hostAliases
		}
	}
	if len(k.imagePullSecrets) > 0 {
		items := make([]map[string]string, 0, len(k.imagePullSecrets))
		for _, s := range k.imagePullSecrets {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			items = append(items, map[string]string{"name": s})
		}
		if len(items) > 0 {
			podSpec := pod["spec"].(map[string]interface{})
			podSpec["imagePullSecrets"] = items
		}
	}
	b, err := json.Marshal(pod)
	if err != nil {
		return "", err
	}
	path := "/api/v1/namespaces/" + url.PathEscape(k.namespace) + "/pods"
	resp, err := k.doJSON(ctx, http.MethodPost, path, b)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("create pod failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return podName, nil
}

func (k *k8sClient) getPod(ctx context.Context, namespace, name string) (*k8sPod, error) {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = k.namespace
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(name)
	resp, err := k.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, os.ErrNotExist
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("get pod failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out k8sPod
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (k *k8sClient) listPodsByLabel(ctx context.Context, namespace, selector string) ([]k8sPod, error) {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = k.namespace
	}
	values := url.Values{}
	if strings.TrimSpace(selector) != "" {
		values.Set("labelSelector", selector)
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	resp, err := k.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("list pods failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var out k8sPodList
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (k *k8sClient) waitForPodStarted(ctx context.Context, namespace, name string, timeout time.Duration) (string, k8sPodRuntimeState, error) {
	deadline := time.Now().Add(timeout)
	for {
		if ctx.Err() != nil {
			return "", k8sPodRuntimeState{}, ctx.Err()
		}
		pod, err := k.getPod(ctx, namespace, name)
		if err == nil {
			state := podRuntimeState(pod)
			phase := strings.ToLower(strings.TrimSpace(pod.Status.Phase))
			switch phase {
			case "running", "succeeded", "failed":
				return strings.TrimSpace(pod.Status.PodIP), state, nil
			}
		}
		if time.Now().After(deadline) {
			return "", k8sPodRuntimeState{}, fmt.Errorf("timeout waiting for pod start")
		}
		time.Sleep(1 * time.Second)
	}
}

func (k *k8sClient) deletePod(ctx context.Context, namespace, name string, graceSeconds int) error {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = k.namespace
	}
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(name)
	payload := map[string]interface{}{
		"gracePeriodSeconds": graceSeconds,
	}
	b, _ := json.Marshal(payload)
	resp, err := k.doJSON(ctx, http.MethodDelete, path, b)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("delete pod failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func (k *k8sClient) podLogs(ctx context.Context, namespace, name string) ([]byte, error) {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = k.namespace
	}
	v := url.Values{}
	v.Set("container", k8sRuntimeContainerName)
	path := "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(name) + "/log?" + v.Encode()
	resp, err := k.doJSON(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("pod logs failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return io.ReadAll(resp.Body)
}

func (k *k8sClient) doJSON(ctx context.Context, method, path string, body []byte) (*http.Response, error) {
	u := strings.TrimRight(k.baseURL, "/") + path
	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
	return k.http.Do(req)
}

func (k *k8sClient) execPod(ctx context.Context, namespace, name string, cmd []string) ([]byte, []byte, int, error) {
	if len(cmd) == 0 {
		return nil, nil, 126, fmt.Errorf("missing exec command")
	}
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		ns = k.namespace
	}
	u, err := url.Parse(k.baseURL)
	if err != nil {
		return nil, nil, 126, err
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = "/api/v1/namespaces/" + url.PathEscape(ns) + "/pods/" + url.PathEscape(name) + "/exec"
	q := url.Values{}
	q.Set("container", k8sRuntimeContainerName)
	q.Set("stdin", "false")
	q.Set("stdout", "true")
	q.Set("stderr", "true")
	q.Set("tty", "false")
	for _, c := range cmd {
		q.Add("command", c)
	}
	u.RawQuery = q.Encode()

	dialer := websocket.Dialer{}
	if tr, ok := k.http.Transport.(*http.Transport); ok && tr != nil {
		dialer.TLSClientConfig = tr.TLSClientConfig
		dialer.Proxy = tr.Proxy
	}
	header := http.Header{}
	if strings.TrimSpace(k.token) != "" {
		header.Set("Authorization", "Bearer "+k.token)
	}
	header.Set("Sec-WebSocket-Protocol", "v4.channel.k8s.io")
	conn, resp, err := dialer.DialContext(ctx, u.String(), header)
	if err != nil {
		if resp != nil {
			defer resp.Body.Close()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			return nil, nil, 126, fmt.Errorf("k8s exec dial failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return nil, nil, 126, err
	}
	defer conn.Close()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := 0
	for {
		if ctx.Err() != nil {
			return stdout.Bytes(), stderr.Bytes(), 126, ctx.Err()
		}
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			if ne, ok := err.(interface{ Timeout() bool }); ok && ne.Timeout() {
				continue
			}
			break
		}
		if msgType != websocket.BinaryMessage && msgType != websocket.TextMessage {
			continue
		}
		if len(payload) == 0 {
			continue
		}
		ch := payload[0]
		data := payload[1:]
		switch ch {
		case 1:
			_, _ = stdout.Write(data)
		case 2:
			_, _ = stderr.Write(data)
		case 3:
			code, message, failed := parseK8sExecStatus(data)
			if failed {
				if code >= 0 {
					exitCode = code
				} else if exitCode == 0 {
					exitCode = 126
				}
				if strings.TrimSpace(message) != "" {
					_, _ = stderr.WriteString(strings.TrimSpace(message))
					_, _ = stderr.WriteString("\n")
				}
			}
		}
	}
	return stdout.Bytes(), stderr.Bytes(), exitCode, nil
}

func parseK8sExecStatus(data []byte) (exitCode int, message string, failed bool) {
	raw := strings.TrimSpace(string(data))
	if raw == "" {
		return -1, "", false
	}
	type statusCause struct {
		Reason  string `json:"reason"`
		Message string `json:"message"`
	}
	type statusDetails struct {
		Causes []statusCause `json:"causes"`
	}
	type statusEnvelope struct {
		Status  string        `json:"status"`
		Message string        `json:"message"`
		Details statusDetails `json:"details"`
	}
	var st statusEnvelope
	if err := json.Unmarshal([]byte(raw), &st); err == nil {
		if strings.EqualFold(strings.TrimSpace(st.Status), "Success") {
			return 0, "", false
		}
		for _, c := range st.Details.Causes {
			if strings.EqualFold(strings.TrimSpace(c.Reason), "ExitCode") {
				if n, err := strconv.Atoi(strings.TrimSpace(c.Message)); err == nil {
					return n, st.Message, true
				}
			}
		}
		if n, ok := parseExecExitCode(st.Message); ok {
			return n, st.Message, true
		}
		return -1, firstNonEmpty(st.Message, raw), true
	}
	if n, ok := parseExecExitCode(raw); ok {
		return n, raw, true
	}
	return -1, raw, true
}

func parseExecExitCode(msg string) (int, bool) {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return 0, false
	}
	needle := "exit code"
	idx := strings.LastIndex(strings.ToLower(msg), needle)
	if idx == -1 {
		return 0, false
	}
	num := strings.TrimSpace(msg[idx+len(needle):])
	n, err := strconv.Atoi(num)
	if err != nil {
		return 0, false
	}
	return n, true
}

func podRuntimeState(pod *k8sPod) k8sPodRuntimeState {
	state := k8sPodRuntimeState{
		Running: strings.EqualFold(strings.TrimSpace(pod.Status.Phase), "Running"),
	}
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.Name != k8sRuntimeContainerName {
			continue
		}
		if cs.State.Running != nil {
			state.Running = true
			if t, ok := parseK8sTime(cs.State.Running.StartedAt); ok {
				state.StartedAt = t
			}
			return state
		}
		if cs.State.Terminated != nil {
			state.Running = false
			state.ExitCode = cs.State.Terminated.ExitCode
			if t, ok := parseK8sTime(cs.State.Terminated.StartedAt); ok {
				state.StartedAt = t
			}
			if t, ok := parseK8sTime(cs.State.Terminated.FinishedAt); ok {
				state.FinishedAt = t
			}
			return state
		}
	}
	switch strings.ToLower(strings.TrimSpace(pod.Status.Phase)) {
	case "succeeded":
		state.Running = false
		state.ExitCode = 0
	case "failed":
		state.Running = false
		if state.ExitCode == 0 {
			state.ExitCode = 1
		}
	}
	return state
}

func parseK8sTime(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func k8sContainerTmpDir(c *Container) string {
	if c == nil {
		return "/tmp"
	}
	return filepath.Join(filepath.Dir(c.Rootfs), "tmp")
}
