package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
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
	if _, meta, pulledRef, err := ensureImageWithFallback(
		r.Context(),
		resolvedRef,
		ref,
		store.stateDir,
		m,
		cfg.trustInsecure,
		ensure,
	); err != nil {
		writeErrorLine(err.Error())
		return
	} else {
		writeStatus("Digest: " + meta.Digest)
		writeStatus("Status: Downloaded newer image for " + pulledRef)
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

func handleImageInspect(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/images/")
	if !strings.HasSuffix(raw, "/json") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw = strings.TrimSuffix(raw, "/json")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ref, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image name")
		return
	}
	resolvedRef := rewriteImageReference(ref, mirrorRules)
	meta, ok, err := findImageMetaByReference(stateDir, ref, resolvedRef)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "image inspect failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "No such image: "+ref)
		return
	}
	repoDigest := meta.Reference + "@" + meta.Digest
	if strings.Contains(meta.Reference, "@") {
		repoDigest = meta.Reference
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"Id":           meta.Digest,
		"RepoTags":     []string{ref, meta.Reference},
		"RepoDigests":  []string{repoDigest},
		"Size":         meta.ContentSize,
		"VirtualSize":  meta.DiskUsage,
		"Os":           "linux",
		"Architecture": "amd64",
		"ContainerConfig": map[string]interface{}{
			"Env": meta.Env,
			"Cmd": meta.Cmd,
		},
		"Config": map[string]interface{}{
			"Env":        meta.Env,
			"Cmd":        meta.Cmd,
			"Entrypoint": meta.Entrypoint,
			"WorkingDir": meta.WorkingDir,
		},
	})
}

func handleImageTag(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule, enabled bool) {
	if !enabled {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/images/")
	if !strings.HasSuffix(raw, "/tag") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw = strings.TrimSuffix(raw, "/tag")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	source, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image name")
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	resolvedSource := rewriteImageReference(source, mirrorRules)
	sourceRecord, ok, err := findImageRecordByReferenceOrDigest(stateDir, []string{source, resolvedSource}, []string{source})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "image tag failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "No such image: "+source)
		return
	}

	repo := strings.TrimSpace(r.URL.Query().Get("repo"))
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	if repo == "" {
		writeError(w, http.StatusBadRequest, "missing repo")
		return
	}
	if tag == "" {
		tag = "latest"
	}
	targetRef := repo + ":" + tag
	if imageTagLooksLikeDigest(tag) {
		targetRef = repo + "@" + tag
	}
	aliasDir := filepath.Join(stateDir, "images", imageAliasKey(targetRef))
	aliasRootfs := filepath.Join(aliasDir, "rootfs")
	_ = os.RemoveAll(aliasDir)
	if err := os.MkdirAll(aliasDir, 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, "image tag failed")
		return
	}
	if err := copyDir(sourceRecord.rootfsDir, aliasRootfs); err != nil {
		_ = os.RemoveAll(aliasDir)
		writeError(w, http.StatusInternalServerError, "image tag failed")
		return
	}
	aliasMeta := sourceRecord.meta
	aliasMeta.Reference = targetRef
	if data, err := json.MarshalIndent(aliasMeta, "", "  "); err != nil {
		_ = os.RemoveAll(aliasDir)
		writeError(w, http.StatusInternalServerError, "image tag failed")
		return
	} else if err := os.WriteFile(filepath.Join(aliasDir, "image.json"), data, 0o644); err != nil {
		_ = os.RemoveAll(aliasDir)
		writeError(w, http.StatusInternalServerError, "image tag failed")
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func handleImagePush(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule, enabled bool) {
	if !enabled {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodPost {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/images/")
	if !strings.HasSuffix(raw, "/push") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw = strings.TrimSuffix(raw, "/push")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	source, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image name")
		return
	}
	source = strings.TrimSpace(source)
	if source == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	tag := strings.TrimSpace(r.URL.Query().Get("tag"))
	refs := []string{source, rewriteImageReference(source, mirrorRules)}
	if tag != "" && !strings.Contains(source, "@") && !imageRefHasTag(source) {
		withTag := source + ":" + tag
		refs = append(refs, withTag, rewriteImageReference(withTag, mirrorRules))
	}
	_, ok, err := findImageRecordByReferenceOrDigest(stateDir, refs, []string{source})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "image push failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "No such image: "+source)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	enc := json.NewEncoder(w)
	_ = enc.Encode(map[string]string{"status": "The push refers to repository [" + source + "]"})
	_ = enc.Encode(map[string]string{"status": "Pushed"})
}

func handleImageDelete(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule, enabled bool) {
	if !enabled {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	raw := strings.TrimPrefix(r.URL.Path, "/images/")
	raw = strings.TrimSuffix(raw, "/")
	if raw == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	ref, err := url.PathUnescape(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid image name")
		return
	}
	ref = strings.TrimSpace(ref)
	if ref == "" {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	resolvedRef := rewriteImageReference(ref, mirrorRules)
	_, ok, err := findImageRecordByReferenceOrDigest(stateDir, []string{ref, resolvedRef}, []string{ref})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "image remove failed")
		return
	}
	if !ok {
		writeError(w, http.StatusNotFound, "No such image: "+ref)
		return
	}
	writeJSON(w, http.StatusOK, []map[string]string{{"Untagged": ref}})
}

func handleImageSubresource(w http.ResponseWriter, r *http.Request, stateDir string, mirrorRules []imageMirrorRule, enableImageMutations bool) {
	path := strings.TrimPrefix(r.URL.Path, "/images/")
	if strings.HasSuffix(path, "/json") {
		handleImageInspect(w, r, stateDir, mirrorRules)
		return
	}
	if strings.HasSuffix(path, "/tag") {
		handleImageTag(w, r, stateDir, mirrorRules, enableImageMutations)
		return
	}
	if strings.HasSuffix(path, "/push") {
		handleImagePush(w, r, stateDir, mirrorRules, enableImageMutations)
		return
	}
	if r.Method == http.MethodDelete {
		handleImageDelete(w, r, stateDir, mirrorRules, enableImageMutations)
		return
	}
	writeError(w, http.StatusNotFound, "not found")
}
