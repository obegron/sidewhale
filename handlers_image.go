package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type imageEnsureFunc func(context.Context, string, string, *metrics, bool) (string, imageMeta, error)

func handleImagesCreate(w http.ResponseWriter, r *http.Request, store *containerStore, m *metrics, cfg appConfig, ensure imageEnsureFunc) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	ref := r.URL.Query().Get("fromImage")
	if ref == "" {
		ref = r.URL.Query().Get("image")
	}
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if ref == "" {
		writeError(w, http.StatusBadRequest, "missing fromImage")
		return
	}
	if tag != "" && !strings.Contains(ref, "@") && !imageRefHasTag(ref) {
		if imageTagLooksLikeDigest(tag) {
			ref = ref + "@" + tag
		} else {
			ref = ref + ":" + tag
		}
	}
	resolvedRef := rewriteImageReference(ref, cfg.mirrorRules)
	if !isImageAllowed(resolvedRef, cfg.allowedPrefixes) {
		writeError(w, http.StatusForbidden, "image not allowed by policy")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	flush := func() {
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}
	writeStatus := func(status string) {
		_ = enc.Encode(map[string]string{
			"status": status,
		})
		flush()
	}
	writeErrorLine := func(message string) {
		_ = enc.Encode(map[string]interface{}{
			"error": message,
			"errorDetail": map[string]string{
				"message": message,
			},
		})
		flush()
	}

	writeStatus("Pulling from " + resolvedRef)
	if _, meta, err := ensure(r.Context(), resolvedRef, store.stateDir, m, cfg.trustInsecure); err != nil {
		writeErrorLine(err.Error())
		return
	} else {
		writeStatus("Digest: " + meta.Digest)
		writeStatus("Status: Downloaded newer image for " + resolvedRef)
	}
}

func imageTagLooksLikeDigest(tag string) bool {
	tag = strings.TrimSpace(strings.ToLower(tag))
	algo, value, ok := strings.Cut(tag, ":")
	if !ok || algo == "" || value == "" {
		return false
	}
	for _, ch := range algo {
		if (ch < 'a' || ch > 'z') && (ch < '0' || ch > '9') && ch != '+' && ch != '-' && ch != '_' && ch != '.' {
			return false
		}
	}
	for _, ch := range value {
		if (ch < 'a' || ch > 'f') && (ch < '0' || ch > '9') {
			return false
		}
	}
	return true
}
