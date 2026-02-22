package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"
)

func monitorK8sPod(containerID, namespace, podName string, store *containerStore, m *metrics, startedAt time.Time) {
	client, err := newInClusterK8sClient()
	if err != nil {
		return
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		c, ok := store.findContainer(containerID)
		if !ok || !c.Running {
			return
		}
		pod, err := client.getPod(context.Background(), namespace, podName)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				exitCode := 137
				finishedAt := time.Now().UTC()
				store.stopProxies(containerID)
				store.markStoppedWithExit(containerID, &exitCode, finishedAt)
				m.mu.Lock()
				if m.running > 0 {
					m.running--
				}
				m.execDurationMs = time.Since(startedAt).Milliseconds()
				m.mu.Unlock()
				return
			}
			continue
		}
		state := podRuntimeState(pod)
		switch strings.ToLower(strings.TrimSpace(pod.Status.Phase)) {
		case "running", "pending":
			if state.Running {
				continue
			}
			continue
		case "succeeded", "failed":
			tryReplayStoppedK8sContainerLocally(c)
			exitCode := state.ExitCode
			finishedAt := time.Now().UTC()
			store.stopProxies(containerID)
			store.markStoppedWithExit(containerID, &exitCode, finishedAt)
			m.mu.Lock()
			if m.running > 0 {
				m.running--
			}
			m.execDurationMs = time.Since(startedAt).Milliseconds()
			m.mu.Unlock()
			return
		}
	}
}

func syncK8sContainerState(ctx context.Context, store *containerStore, c *Container) (*Container, error) {
	if c == nil || strings.TrimSpace(c.K8sPodName) == "" {
		return c, nil
	}
	client, err := newInClusterK8sClient()
	if err != nil {
		return c, err
	}
	pod, err := client.getPod(ctx, c.K8sNamespace, c.K8sPodName)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			c.Running = false
			c.Pid = 0
			if c.ExitCode == 0 {
				c.ExitCode = 137
			}
			if c.FinishedAt.IsZero() {
				c.FinishedAt = time.Now().UTC()
			}
			c.K8sPodIP = ""
			store.stopProxies(c.ID)
			_ = store.saveContainer(c)
			updated, _ := store.findContainer(c.ID)
			if updated != nil {
				return updated, nil
			}
			return c, nil
		}
		return c, err
	}
	state := podRuntimeState(pod)
	c.K8sPodIP = strings.TrimSpace(pod.Status.PodIP)
	c.Running = state.Running
	if state.StartedAt.IsZero() {
		if c.StartedAt.IsZero() {
			c.StartedAt = time.Now().UTC()
		}
	} else {
		c.StartedAt = state.StartedAt
	}
	if state.Running {
		c.ExitCode = 0
		c.FinishedAt = time.Time{}
	} else {
		tryReplayStoppedK8sContainerLocally(c)
		c.Pid = 0
		c.ExitCode = state.ExitCode
		if state.FinishedAt.IsZero() {
			if c.FinishedAt.IsZero() {
				c.FinishedAt = time.Now().UTC()
			}
		} else {
			c.FinishedAt = state.FinishedAt
		}
		store.stopProxies(c.ID)
	}
	_ = store.saveContainer(c)
	updated, _ := store.findContainer(c.ID)
	if updated != nil {
		return updated, nil
	}
	return c, nil
}
