package main

import (
	"context"
	"net/http"
)

// Naming aliases keep old internal handlers stable while exposing clearer intent in routing.
func handleContainerCreate(w http.ResponseWriter, r *http.Request, store *containerStore, runtimeBackend string, allowedPrefixes []string, mirrorRules []imageMirrorRule, unixSocketPath string, trustInsecure bool, ensureImage func(context.Context, string, string, *metrics, bool) (string, imageMeta, error)) {
	handleCreate(w, r, store, runtimeBackend, allowedPrefixes, mirrorRules, unixSocketPath, trustInsecure, ensureImage)
}

func handleContainerStart(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, limits runtimeLimits, runtimeBackend, k8sRuntimeNamespace string, k8sImagePullSecrets []string, id string) {
	handleStart(w, r, store, m, limits, runtimeBackend, k8sRuntimeNamespace, k8sImagePullSecrets, id)
}

func handleContainerStop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleStop(w, r, store, id)
}

func handleContainerKill(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleKill(w, r, store, id)
}

func handleContainerDelete(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleDelete(w, r, store, id)
}

func handleContainerInspect(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleJSON(w, r, store, id)
}

func handleContainerTop(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleTop(w, r, store, id)
}

func handleContainerLogs(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleLogs(w, r, store, id)
}

func handleContainerStats(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleStats(w, r, store, id)
}

func handleContainerWait(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	handleWait(w, r, store, id)
}

func handleContainerEvents(w http.ResponseWriter, r *http.Request) {
	handleEvents(w, r)
}
