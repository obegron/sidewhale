package main

import (
	"strings"
	"time"
)

func containerStartedAt(c *Container) time.Time {
	if c != nil && !c.StartedAt.IsZero() {
		return c.StartedAt
	}
	if c != nil && !c.Created.IsZero() {
		return c.Created
	}
	return time.Time{}
}

func containerFinishedAt(c *Container) time.Time {
	if c == nil {
		return time.Time{}
	}
	if c.Running {
		return time.Time{}
	}
	if !c.FinishedAt.IsZero() {
		return c.FinishedAt
	}
	if !c.Created.IsZero() {
		return c.Created
	}
	return time.Time{}
}

func clonePortTargets(in map[int]string) map[int]string {
	out := make(map[int]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func refreshNetworkAliasHosts(store *containerStore, containerID string) {
	if store == nil || strings.TrimSpace(containerID) == "" {
		return
	}
	for _, id := range store.containersSharingNetworks(containerID) {
		c, ok := store.findContainer(id)
		if !ok || c == nil || !c.Running {
			continue
		}
		_ = writeContainerIdentityFilesWithAliasesAndHosts(c.Rootfs, c.Hostname, store.peerAliasesForContainer(c.ID), c.ExtraHosts)
	}
}
