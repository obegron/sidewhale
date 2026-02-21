package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

func reconcileK8sRuntime(store *containerStore, m *metrics, namespaceOverride string, cleanupOrphans bool) {
	client, err := newInClusterK8sClient()
	if err != nil {
		fmt.Printf("sidewhale: k8s reconcile skipped: %v\n", err)
		return
	}
	if ns := strings.TrimSpace(namespaceOverride); ns != "" {
		client.namespace = ns
	}
	stateIDs := map[string]struct{}{}
	for _, id := range store.listContainerIDs() {
		stateIDs[id] = struct{}{}
	}
	if cleanupOrphans {
		pods, err := client.listPodsByLabel(context.Background(), client.namespace, "sidewhale.managed=true")
		if err != nil {
			fmt.Printf("sidewhale: k8s orphan scan failed: %v\n", err)
		} else {
			for _, pod := range pods {
				cid := strings.TrimSpace(pod.Metadata.Labels["sidewhale.container-id"])
				if cid == "" {
					continue
				}
				if _, ok := stateIDs[cid]; ok {
					continue
				}
				if err := client.deletePod(context.Background(), client.namespace, pod.Metadata.Name, 0); err != nil {
					fmt.Printf("sidewhale: k8s orphan delete failed pod=%s err=%v\n", pod.Metadata.Name, err)
					continue
				}
				fmt.Printf("sidewhale: deleted orphan worker pod=%s\n", pod.Metadata.Name)
			}
		}
	}
	running := 0
	for _, id := range store.listContainerIDs() {
		c, ok := store.findContainer(id)
		if !ok || c == nil || strings.TrimSpace(c.K8sPodName) == "" {
			continue
		}
		pod, err := client.getPod(context.Background(), c.K8sNamespace, c.K8sPodName)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				store.stopProxies(c.ID)
				c.Running = false
				c.Pid = 0
				if c.ExitCode == 0 {
					c.ExitCode = 137
				}
				if c.FinishedAt.IsZero() {
					c.FinishedAt = time.Now().UTC()
				}
				c.K8sPodIP = ""
				c.PortTargets = nil
				_ = store.saveContainer(c)
				continue
			}
			fmt.Printf("sidewhale: k8s reconcile pod lookup failed container=%s pod=%s err=%v\n", c.ID, c.K8sPodName, err)
			continue
		}
		state := podRuntimeState(pod)
		c.K8sPodIP = strings.TrimSpace(pod.Status.PodIP)
		c.Running = state.Running
		c.Pid = 0
		if !state.StartedAt.IsZero() {
			c.StartedAt = state.StartedAt
		}
		if state.Running {
			targets := map[int]string{}
			if c.K8sPodIP != "" {
				for cp := range c.Ports {
					targets[cp] = fmt.Sprintf("%s:%d", c.K8sPodIP, cp)
				}
			}
			store.stopProxies(c.ID)
			if len(targets) > 0 {
				proxies, err := startPortProxies(c.Ports, targets)
				if err != nil {
					fmt.Printf("sidewhale: k8s reconcile proxy restore failed container=%s err=%v\n", c.ID, err)
				} else {
					store.setProxies(c.ID, proxies)
					c.PortTargets = targets
				}
			}
			c.ExitCode = 0
			c.FinishedAt = time.Time{}
			running++
		} else {
			store.stopProxies(c.ID)
			c.PortTargets = nil
			c.ExitCode = state.ExitCode
			if !state.FinishedAt.IsZero() {
				c.FinishedAt = state.FinishedAt
			} else if c.FinishedAt.IsZero() {
				c.FinishedAt = time.Now().UTC()
			}
		}
		_ = store.saveContainer(c)
	}
	m.mu.Lock()
	m.running = running
	m.mu.Unlock()
	fmt.Printf("sidewhale: k8s reconcile completed running=%d\n", running)
}
