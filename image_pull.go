package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

var imagePullLocks sync.Map

func ensureImage(ctx context.Context, ref string, stateDir string, m *metrics, trustInsecure bool) (string, imageMeta, error) {
	ref = strings.TrimSpace(ref)
	if rec, ok, err := findImageRecordByReferenceOrDigest(stateDir, []string{ref}, []string{ref}); err == nil && ok {
		return rec.rootfsDir, rec.meta, nil
	}
	parsed, err := name.ParseReference(ref)
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("invalid image reference: %w", err)
	}
	remoteOptions := []remote.Option{
		remote.WithContext(ctx),
		remote.WithPlatform(v1.Platform{
			OS:           "linux",
			Architecture: "amd64",
		}),
	}
	if trustInsecure {
		remoteOptions = append(remoteOptions, remote.WithTransport(insecurePullTransport()))
	}
	image, err := remote.Image(parsed, remoteOptions...)
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("image pull failed: %w", err)
	}
	digest, err := image.Digest()
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("image digest failed: %w", err)
	}

	digestKey := strings.ReplaceAll(digest.String(), ":", "_")
	lock := acquireImagePullLock(digestKey)
	defer lock.Unlock()

	imageDir := filepath.Join(stateDir, "images", digestKey)
	rootfsDir := filepath.Join(imageDir, "rootfs")
	metaPath := filepath.Join(imageDir, "image.json")
	if _, err := os.Stat(rootfsDir); err == nil {
		meta := imageMeta{}
		if data, err := os.ReadFile(metaPath); err == nil {
			_ = json.Unmarshal(data, &meta)
		}
		if meta.Extractor == extractorVersion {
			if meta.DiskUsage == 0 {
				if usage, usageErr := dirSize(rootfsDir); usageErr == nil {
					meta.DiskUsage = usage
					if data, marshalErr := json.MarshalIndent(meta, "", "  "); marshalErr == nil {
						_ = os.WriteFile(metaPath, data, 0o644)
					}
				}
			}
			return rootfsDir, meta, nil
		}
		_ = os.RemoveAll(rootfsDir)
	}

	start := time.Now()
	if err := os.MkdirAll(imageDir, 0o755); err != nil {
		return "", imageMeta{}, fmt.Errorf("image dir init failed: %w", err)
	}
	tmpRootfs := rootfsDir + ".tmp"
	_ = os.RemoveAll(tmpRootfs)
	if err := os.MkdirAll(tmpRootfs, 0o755); err != nil {
		return "", imageMeta{}, fmt.Errorf("temp rootfs init failed: %w", err)
	}

	layers, err := image.Layers()
	if err != nil {
		return "", imageMeta{}, fmt.Errorf("layer list failed: %w", err)
	}
	var contentSize int64
	dirModes := map[string]dirAttributes{}
	for _, layer := range layers {
		if size, sizeErr := layer.Size(); sizeErr == nil && size > 0 {
			contentSize += size
		}
		if err := extractLayer(tmpRootfs, layer, dirModes); err != nil {
			_ = os.RemoveAll(tmpRootfs)
			return "", imageMeta{}, err
		}
	}
	if err := applyDirModes(dirModes); err != nil {
		_ = os.RemoveAll(tmpRootfs)
		return "", imageMeta{}, err
	}
	if err := os.Rename(tmpRootfs, rootfsDir); err != nil {
		_ = os.RemoveAll(tmpRootfs)
		return "", imageMeta{}, fmt.Errorf("rootfs finalize failed: %w", err)
	}
	diskUsage, _ := dirSize(rootfsDir)

	meta := imageMeta{
		Reference:   ref,
		Digest:      digest.String(),
		Extractor:   extractorVersion,
		ContentSize: contentSize,
		DiskUsage:   diskUsage,
	}
	if cfg, err := image.ConfigFile(); err == nil && cfg != nil {
		meta.Entrypoint = cfg.Config.Entrypoint
		meta.Cmd = cfg.Config.Cmd
		meta.Env = cfg.Config.Env
		meta.ExposedPorts = cfg.Config.ExposedPorts
		meta.WorkingDir = cfg.Config.WorkingDir
		meta.User = cfg.Config.User
	}
	if data, err := json.MarshalIndent(meta, "", "  "); err == nil {
		_ = os.WriteFile(metaPath, data, 0o644)
	}

	if m != nil {
		m.mu.Lock()
		m.pullDurationMs = time.Since(start).Milliseconds()
		m.mu.Unlock()
	}
	return rootfsDir, meta, nil
}

func ensureImageWithFallback(
	ctx context.Context,
	primaryRef string,
	fallbackRef string,
	stateDir string,
	m *metrics,
	trustInsecure bool,
	ensure func(context.Context, string, string, *metrics, bool) (string, imageMeta, error),
) (string, imageMeta, string, error) {
	candidates := uniqueImageRefs(primaryRef, fallbackRef)
	if len(candidates) == 0 {
		return "", imageMeta{}, "", fmt.Errorf("missing image reference")
	}
	var lastErr error
	for i, candidate := range candidates {
		rootfs, meta, err := ensure(ctx, candidate, stateDir, m, trustInsecure)
		if err == nil {
			return rootfs, meta, candidate, nil
		}
		lastErr = err
		if i == 0 && len(candidates) > 1 && shouldFallbackAfterMirrorDigestMiss(candidates[0], candidates[1], err) {
			continue
		}
		return "", imageMeta{}, "", err
	}
	return "", imageMeta{}, "", lastErr
}

func uniqueImageRefs(refs ...string) []string {
	out := make([]string, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func shouldFallbackAfterMirrorDigestMiss(primaryRef string, fallbackRef string, err error) bool {
	if strings.TrimSpace(primaryRef) == "" || strings.TrimSpace(fallbackRef) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(primaryRef), strings.TrimSpace(fallbackRef)) {
		return false
	}
	if !isDigestImageReference(primaryRef) {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "manifest_unknown") || strings.Contains(msg, "manifest unknown")
}

func isDigestImageReference(ref string) bool {
	ref = strings.TrimSpace(strings.ToLower(ref))
	return strings.Contains(ref, "@sha256:")
}

func acquireImagePullLock(key string) *sync.Mutex {
	lockAny, _ := imagePullLocks.LoadOrStore(key, &sync.Mutex{})
	lock := lockAny.(*sync.Mutex)
	lock.Lock()
	return lock
}

func insecurePullTransport() http.RoundTripper {
	base, _ := http.DefaultTransport.(*http.Transport)
	if base == nil {
		return &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // explicitly enabled by --trust-insecure
		}
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{} //nolint:gosec // explicit opt-in below
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	}
	transport.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // explicitly enabled by --trust-insecure
	return transport
}
