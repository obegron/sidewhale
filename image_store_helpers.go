package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

func listImages(stateDir string) ([]map[string]interface{}, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		return nil, err
	}
	out := make([]map[string]interface{}, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(imageRoot, entry.Name(), "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		if meta.DiskUsage == 0 {
			if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
				meta.DiskUsage = size
			}
		}
		created := int64(0)
		if info, statErr := os.Stat(metaPath); statErr == nil {
			created = info.ModTime().Unix()
		}
		out = append(out, map[string]interface{}{
			"Id":          meta.Digest,
			"RepoTags":    []string{meta.Reference},
			"Created":     created,
			"Size":        meta.ContentSize,
			"VirtualSize": meta.DiskUsage,
			"SharedSize":  0,
		})
	}
	return out, nil
}

func findImageMetaByReference(stateDir string, refs ...string) (imageMeta, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageMeta{}, false, nil
		}
		return imageMeta{}, false, err
	}
	wanted := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wanted[ref] = struct{}{}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(imageRoot, entry.Name(), "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		if _, ok := wanted[meta.Reference]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
	}
	return imageMeta{}, false, nil
}

func findImageMetaByReferenceOrDigest(stateDir string, refs []string, digests []string) (imageMeta, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageMeta{}, false, nil
		}
		return imageMeta{}, false, err
	}
	wantedRefs := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wantedRefs[ref] = struct{}{}
	}
	wantedDigests := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		digest = strings.TrimSpace(digest)
		if digest == "" {
			continue
		}
		wantedDigests[digest] = struct{}{}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		metaPath := filepath.Join(imageRoot, entry.Name(), "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		if _, ok := wantedRefs[meta.Reference]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
		if _, ok := wantedDigests[meta.Digest]; ok {
			if meta.DiskUsage == 0 {
				if size, sizeErr := dirSize(filepath.Join(imageRoot, entry.Name(), "rootfs")); sizeErr == nil {
					meta.DiskUsage = size
				}
			}
			return meta, true, nil
		}
	}
	return imageMeta{}, false, nil
}

type imageRecord struct {
	imageDir  string
	rootfsDir string
	metaPath  string
	meta      imageMeta
}

func findImageRecordByReferenceOrDigest(stateDir string, refs []string, digests []string) (imageRecord, bool, error) {
	imageRoot := filepath.Join(stateDir, "images")
	entries, err := os.ReadDir(imageRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return imageRecord{}, false, nil
		}
		return imageRecord{}, false, err
	}
	wantedRefs := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		wantedRefs[ref] = struct{}{}
	}
	wantedDigests := make(map[string]struct{}, len(digests))
	for _, digest := range digests {
		digest = strings.TrimSpace(digest)
		if digest == "" {
			continue
		}
		wantedDigests[digest] = struct{}{}
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		imageDir := filepath.Join(imageRoot, entry.Name())
		metaPath := filepath.Join(imageDir, "image.json")
		data, err := os.ReadFile(metaPath)
		if err != nil {
			continue
		}
		var meta imageMeta
		if err := json.Unmarshal(data, &meta); err != nil {
			continue
		}
		_, refMatch := wantedRefs[meta.Reference]
		_, digestMatch := wantedDigests[meta.Digest]
		if !refMatch && !digestMatch {
			continue
		}
		rootfsDir := filepath.Join(imageDir, "rootfs")
		if meta.DiskUsage == 0 {
			if size, sizeErr := dirSize(rootfsDir); sizeErr == nil {
				meta.DiskUsage = size
			}
		}
		return imageRecord{
			imageDir:  imageDir,
			rootfsDir: rootfsDir,
			metaPath:  metaPath,
			meta:      meta,
		}, true, nil
	}
	return imageRecord{}, false, nil
}

func imageAliasKey(ref string) string {
	sum := sha256.Sum256([]byte(ref))
	return "ref_" + hex.EncodeToString(sum[:12])
}

func mergeExposedPorts(base, override map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{})
	for k, v := range base {
		out[k] = v
	}
	for k, v := range override {
		out[k] = v
	}
	return out
}
