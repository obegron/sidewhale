package main

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

// isSafeLinkTarget checks whether a link target from a tar header
// resolves to a location within the provided destination directory.
func isSafeLinkTarget(linkname, symlinkTargetPath, dst string) (bool, error) {
	// 1. Reject absolute link names directly.
	if filepath.IsAbs(linkname) {
		return false, fmt.Errorf("absolute symlink target '%s' is not allowed", linkname)
	}

	// 2. Resolve linkname relative to the directory where the symlink itself will be placed.
	//    symlinkTargetPath is the full path in the extraction directory where the symlink will be created.
	symlinkDir := filepath.Dir(symlinkTargetPath)
	resolvedLinkTarget := filepath.Clean(filepath.Join(symlinkDir, linkname))

	// 3. Use isPathWithinBase to check if this resolved target is within the overall extraction destination (dst).
	ok, err := isPathWithinBase(dst, resolvedLinkTarget)
	if err != nil {
		return false, fmt.Errorf("error checking symlink target safety: %w", err)
	}
	if !ok {
		return false, fmt.Errorf("symlink target '%s' resolves outside base directory '%s'", linkname, dst)
	}

	return true, nil
}

func handleArchiveGet(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	queryPath := strings.TrimSpace(r.URL.Query().Get("path"))
	containerPath := normalizeArchiveContainerPath(queryPath)
	targetPath, err := resolvePathInContainerFS(c, containerPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid archive path")
		return
	}

	// In k8s mode, read archive directly from the running pod when available.
	if strings.TrimSpace(c.K8sPodName) != "" {
		client, err := newInClusterK8sClient()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "archive read failed: "+err.Error())
			return
		}
		if err := writeArchiveFromK8sPod(w, r, client, c, containerPath); err != nil {
			// For stopped containers, the pod may be gone while a local shadow rootfs
			// still exists. Fall back to local filesystem in that case.
			if c.Running {
				if errors.Is(err, fs.ErrNotExist) {
					writeError(w, http.StatusNotFound, "path not found")
					return
				}
				writeError(w, http.StatusInternalServerError, "archive read failed: "+err.Error())
				return
			}
			fmt.Printf("sidewhale: archive get fallback container=%s path=%s k8s_err=%v\n", c.ID, containerPath, err)
		} else {
			return
		}
	}

	info, err := os.Lstat(targetPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			writeError(w, http.StatusNotFound, "path not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "stat failed")
		return
	}

	linkTarget := ""
	if info.Mode()&os.ModeSymlink != 0 {
		if link, linkErr := os.Readlink(targetPath); linkErr == nil {
			linkTarget = link
		}
	}
	statPayload := map[string]interface{}{
		"name":       filepath.Base(strings.TrimRight(filepath.Clean(queryPath), string(os.PathSeparator))),
		"size":       info.Size(),
		"mode":       uint32(info.Mode()),
		"mtime":      info.ModTime().UTC().Format(time.RFC3339Nano),
		"linkTarget": linkTarget,
	}
	statJSON, err := json.Marshal(statPayload)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "stat encode failed")
		return
	}

	tarName := filepath.Base(filepath.Clean(queryPath))
	if tarName == "." || tarName == string(os.PathSeparator) {
		tarName = filepath.Base(targetPath)
	}
	if tarName == "." || tarName == string(os.PathSeparator) || tarName == "" {
		tarName = "archive"
	}
	tarName = path.Clean("/" + filepath.ToSlash(tarName))
	tarName = strings.TrimPrefix(tarName, "/")

	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.WriteHeader(http.StatusOK)

	tw := tar.NewWriter(w)
	defer tw.Close()
	if err := writePathToTar(tw, targetPath, tarName); err != nil {
		return
	}
}

func handleArchivePut(w http.ResponseWriter, r *http.Request, store *containerStore, id string) {
	c, ok := store.findContainer(id)
	if !ok {
		writeError(w, http.StatusNotFound, "container not found")
		return
	}
	queryPath := strings.TrimSpace(r.URL.Query().Get("path"))
	containerPath := normalizeArchiveContainerPath(queryPath)
	targetPath, err := resolvePathInContainerFS(c, containerPath)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid archive path")
		return
	}
	tmpBase := filepath.Join(filepath.Dir(c.Rootfs), "tmp")
	dirHint := strings.HasSuffix(queryPath, "/")
	fmt.Printf("sidewhale: archive put begin container=%s path=%s content_length=%d pod=%s\n", c.ID, containerPath, r.ContentLength, c.K8sPodName)
	top, touched, err := extractArchiveToPath(r.Body, targetPath, tmpBase, dirHint, containerPath == "/", func(dst string) string {
		return mapArchiveDestinationPath(c, dst)
	})
	if err != nil {
		fmt.Printf("sidewhale: archive put extract failed container=%s path=%s err=%v\n", c.ID, containerPath, err)
		writeError(w, http.StatusInternalServerError, "archive extract failed: "+err.Error())
		return
	}

	trackedPaths := deduplicatePaths(localPathsToContainerPaths(c, touched))
	if len(trackedPaths) == 0 {
		if containerPath == "/" {
			for _, entry := range top {
				entry = strings.Trim(strings.TrimSpace(entry), "/")
				if entry == "" {
					continue
				}
				trackedPaths = append(trackedPaths, "/"+entry)
			}
		} else {
			trackedPaths = append(trackedPaths, containerPath)
		}
		trackedPaths = deduplicatePaths(trackedPaths)
	}
	for _, p := range trackedPaths {
		addArchivePath(c, p)
	}
	fmt.Printf("sidewhale: archive put container=%s path=%s pod=%s\n", c.ID, containerPath, c.K8sPodName)
	if err := store.saveContainer(c); err != nil {
		writeError(w, http.StatusInternalServerError, "state write failed")
		return
	}

	if strings.TrimSpace(c.K8sPodName) != "" && c.Running {
		client, err := newInClusterK8sClient()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "archive sync failed: "+err.Error())
			return
		}
		for _, archivePath := range trackedPaths {
			if err := syncArchivePathToK8sPod(r.Context(), client, c, archivePath); err != nil {
				fmt.Printf("sidewhale: archive immediate sync failed container=%s path=%s err=%v\n", c.ID, archivePath, err)
				writeError(w, http.StatusInternalServerError, "archive sync failed: "+err.Error())
				return
			}
		}
	} else if strings.TrimSpace(c.K8sPodName) != "" && !c.Running {
		fmt.Printf("sidewhale: archive put skip-k8s-sync container=%s reason=not_running\n", c.ID)
	}
	w.WriteHeader(http.StatusOK)
}

func resolvePathInContainerFS(c *Container, requested string) (string, error) {
	req := strings.TrimSpace(requested)
	if req == "" {
		return "", fmt.Errorf("path is required")
	}
	clean := path.Clean("/" + req)

	if clean == "/tmp" || strings.HasPrefix(clean, "/tmp/") {
		relTmp := strings.TrimPrefix(clean, "/tmp")
		relTmp = strings.TrimPrefix(relTmp, "/")
		return resolvePathUnder(containerTmpDir(c), relTmp)
	}

	relRoot := strings.TrimPrefix(clean, "/")
	if relRoot == "." || relRoot == "" {
		relRoot = ""
	}
	return resolvePathUnder(c.Rootfs, relRoot)
}

func normalizeArchiveContainerPath(requested string) string {
	req := strings.TrimSpace(requested)
	if req == "" {
		return ""
	}
	clean := path.Clean("/" + req)
	if clean == "." {
		return "/"
	}
	return clean
}

func resolvePathUnder(base string, rel string) (string, error) {
	full := filepath.Join(base, filepath.FromSlash(rel))
	baseClean := filepath.Clean(base)
	relCheck, err := filepath.Rel(baseClean, full)
	if err != nil {
		return "", err
	}
	if relCheck == ".." || strings.HasPrefix(relCheck, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes base")
	}
	return full, nil
}

func extractArchiveToPath(r io.Reader, targetPath, tmpBase string, targetDirHint bool, preserveTopDir bool, mapDst func(string) string) ([]string, []string, error) {
	base := strings.TrimSpace(tmpBase)
	if base == "" {
		base = os.TempDir()
	}
	if err := os.MkdirAll(base, 0o755); err != nil {
		return nil, nil, err
	}
	tmpDir, err := os.MkdirTemp(base, "sidewhale-archive-*")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(tmpDir)

	top, err := untarToDir(r, tmpDir)
	if err != nil {
		return nil, nil, err
	}
	if len(top) == 0 {
		return top, nil, nil
	}
	touched := []string{}
	addTouched := func(srcPath, dstPath string) error {
		paths, err := collectSyncTargets(srcPath, dstPath)
		if err != nil {
			return err
		}
		touched = append(touched, paths...)
		return nil
	}

	info, statErr := os.Stat(targetPath)
	targetExists := statErr == nil
	targetBase := mapArchivePath(targetPath, mapDst)
	if statErr != nil && !errors.Is(statErr, fs.ErrNotExist) {
		return nil, nil, statErr
	}
	if !targetExists && targetDirHint {
		if err := os.MkdirAll(targetBase, 0o755); err != nil {
			return nil, nil, err
		}
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			src := filepath.Join(tmpDir, entry.Name())
			dst := filepath.Join(targetPath, entry.Name())
			if err := copyArchiveFSNode(tmpDir, src, targetBase, mapArchivePath(dst, mapDst)); err != nil {
				return nil, nil, err
			}
			if err := addTouched(src, dst); err != nil {
				return nil, nil, err
			}
		}
		return top, deduplicatePaths(touched), nil
	}
	if targetExists && info.IsDir() {
		entries, err := os.ReadDir(tmpDir)
		if err != nil {
			return nil, nil, err
		}
		if err := os.MkdirAll(targetBase, 0o755); err != nil {
			return nil, nil, err
		}
		// Docker archive extraction into an existing directory behaves like "extract contents".
		// When the archive has a single top-level directory, flatten it so files land directly
		// under the destination directory (for example /etc/mysql/conf.d/my.cnf).
		if !preserveTopDir && len(entries) == 1 && entries[0].IsDir() {
			innerEntries, err := os.ReadDir(filepath.Join(tmpDir, entries[0].Name()))
			if err != nil {
				return nil, nil, err
			}
			for _, entry := range innerEntries {
				src := filepath.Join(tmpDir, entries[0].Name(), entry.Name())
				dst := filepath.Join(targetPath, entry.Name())
				if err := copyArchiveFSNode(tmpDir, src, targetBase, mapArchivePath(dst, mapDst)); err != nil {
					return nil, nil, err
				}
				if err := addTouched(src, dst); err != nil {
					return nil, nil, err
				}
			}
			return top, deduplicatePaths(touched), nil
		}
		for _, entry := range entries {
			src := filepath.Join(tmpDir, entry.Name())
			dst := filepath.Join(targetPath, entry.Name())
			if err := copyArchiveFSNode(tmpDir, src, targetBase, mapArchivePath(dst, mapDst)); err != nil {
				return nil, nil, err
			}
			if err := addTouched(src, dst); err != nil {
				return nil, nil, err
			}
		}
		return top, deduplicatePaths(touched), nil
	}
	if len(top) == 1 {
		src := filepath.Join(tmpDir, top[0])
		dstBase := targetBase
		parent := filepath.Dir(targetBase)
		if err := ensurePathUnderBase(dstBase, parent); err != nil {
			dstBase = parent
		}
		if err := copyFSNode(tmpDir, src, dstBase, targetBase); err != nil {
			return nil, nil, err
		}
		if err := addTouched(src, targetPath); err != nil {
			return nil, nil, err
		}
		return top, deduplicatePaths(touched), nil
	}
	if err := os.MkdirAll(targetBase, 0o755); err != nil {
		return nil, nil, err
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return nil, nil, err
	}
	for _, entry := range entries {
		src := filepath.Join(tmpDir, entry.Name())
		dst := filepath.Join(targetPath, entry.Name())
		if err := copyArchiveFSNode(tmpDir, src, targetBase, mapArchivePath(dst, mapDst)); err != nil {
			return nil, nil, err
		}
		if err := addTouched(src, dst); err != nil {
			return nil, nil, err
		}
	}
	return top, deduplicatePaths(touched), nil
}

func copyArchiveFSNode(srcBase, src, targetBase, targetPath string) error {
	dstBase := targetBase
	if err := ensurePathUnderBase(dstBase, targetPath); err != nil {
		parent := filepath.Dir(targetBase)
		if ensurePathUnderBase(parent, targetPath) == nil {
			dstBase = parent
		}
	}
	return copyFSNode(srcBase, src, dstBase, targetPath)
}

func collectSyncTargets(srcPath, dstPath string) ([]string, error) {
	info, err := os.Lstat(srcPath)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{filepath.ToSlash(dstPath)}, nil
	}
	out := []string{}
	err = filepath.WalkDir(srcPath, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(srcPath, p)
		if err != nil {
			return err
		}
		out = append(out, filepath.ToSlash(filepath.Join(dstPath, rel)))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func deduplicatePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	seen := map[string]struct{}{}
	for _, p := range paths {
		p = normalizeArchiveContainerPath(filepath.ToSlash(strings.TrimSpace(p)))
		if p == "" || p == "/" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func localPathsToContainerPaths(c *Container, paths []string) []string {
	if c == nil {
		return nil
	}
	rootfs := filepath.Clean(c.Rootfs)
	tmp := filepath.Clean(containerTmpDir(c))
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = filepath.Clean(strings.TrimSpace(p))
		if p == "" {
			continue
		}
		if rel, err := filepath.Rel(tmp, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			if rel == "." || rel == "" {
				out = append(out, "/tmp")
			} else {
				out = append(out, "/tmp/"+filepath.ToSlash(rel))
			}
			continue
		}
		if rel, err := filepath.Rel(rootfs, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			if rel == "." || rel == "" {
				out = append(out, "/")
			} else {
				out = append(out, "/"+filepath.ToSlash(rel))
			}
			continue
		}
	}
	return out
}

func mapArchivePath(path string, mapDst func(string) string) string {
	if mapDst == nil {
		return path
	}
	mapped := mapDst(path)
	if strings.TrimSpace(mapped) == "" {
		return path
	}
	return mapped
}

func mapArchiveDestinationPath(c *Container, dst string) string {
	if c == nil {
		return dst
	}
	rootTmp := filepath.Clean(filepath.Join(c.Rootfs, "tmp"))
	cleanDst := filepath.Clean(dst)
	if cleanDst != rootTmp && !strings.HasPrefix(cleanDst, rootTmp+string(filepath.Separator)) {
		return dst
	}
	rel, err := filepath.Rel(rootTmp, cleanDst)
	if err != nil {
		return dst
	}
	mapped, err := resolvePathUnder(containerTmpDir(c), rel)
	if err != nil {
		return dst
	}
	return mapped
}

func addArchivePath(c *Container, containerPath string) {
	if c == nil {
		return
	}
	cp := normalizeArchiveContainerPath(containerPath)
	if cp == "" {
		return
	}
	for _, existing := range c.ArchivePaths {
		if existing == cp {
			return
		}
	}
	c.ArchivePaths = append(c.ArchivePaths, cp)
}

func syncPendingArchivePathsToK8sPod(ctx context.Context, client *k8sClient, c *Container) error {
	if c == nil || client == nil || strings.TrimSpace(c.K8sPodName) == "" {
		return nil
	}
	for _, containerPath := range c.ArchivePaths {
		fmt.Printf("sidewhale: archive replay container=%s path=%s pod=%s\n", c.ID, containerPath, c.K8sPodName)
		if err := syncArchivePathToK8sPod(ctx, client, c, containerPath); err != nil {
			return err
		}
	}
	return nil
}

func syncArchivePathToK8sPod(ctx context.Context, client *k8sClient, c *Container, containerPath string) error {
	if c == nil || client == nil || strings.TrimSpace(c.K8sPodName) == "" {
		return nil
	}
	containerPath = normalizeArchiveContainerPath(containerPath)
	if containerPath == "" || containerPath == "/" {
		return nil
	}
	localPath, err := resolvePathInContainerFS(c, containerPath)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(localPath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	nameInTar := path.Base(containerPath)
	if nameInTar == "." || nameInTar == "/" || nameInTar == "" {
		nameInTar = filepath.Base(localPath)
	}
	dstParent := path.Dir(containerPath)
	if dstParent == "." || dstParent == "" {
		dstParent = "/"
	}

	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		zw := gzip.NewWriter(pw)
		tw := tar.NewWriter(zw)
		if err := writePathToTar(tw, localPath, nameInTar); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := tw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
		if err := zw.Close(); err != nil {
			_ = pw.CloseWithError(err)
			return
		}
	}()

	cmd := []string{"sh", "-lc", "mkdir -p " + shellQuote(dstParent) + " && tar -xzf - -C " + shellQuote(dstParent)}
	out, errOut, code, err := client.execPodWithInput(ctx, c.K8sNamespace, c.K8sPodName, cmd, pr)
	if err != nil {
		return err
	}
	fmt.Printf("sidewhale: archive k8s sync container=%s path=%s exit=%d stderr=%q\n", c.ID, containerPath, code, strings.TrimSpace(string(errOut)))
	if code != 0 {
		return fmt.Errorf("k8s archive sync failed path=%s exit=%d stderr=%s stdout=%s", containerPath, code, strings.TrimSpace(string(errOut)), strings.TrimSpace(string(out)))
	}
	return nil
}

func writeArchiveFromK8sPod(w http.ResponseWriter, r *http.Request, client *k8sClient, c *Container, containerPath string) error {
	if client == nil || c == nil {
		return fmt.Errorf("invalid archive context")
	}
	containerPath = normalizeArchiveContainerPath(containerPath)
	if containerPath == "" {
		return fmt.Errorf("missing path")
	}
	dstParent := path.Dir(containerPath)
	if dstParent == "." || dstParent == "" {
		dstParent = "/"
	}
	name := path.Base(containerPath)
	if name == "." || name == "" {
		name = path.Base(path.Clean(containerPath))
	}
	if name == "." || name == "/" || name == "" {
		name = "archive"
	}

	cmd := []string{"sh", "-lc", "tar -cf - -C " + shellQuote(dstParent) + " " + shellQuote(name)}
	out, errOut, code, err := client.execPod(r.Context(), c.K8sNamespace, c.K8sPodName, cmd)
	if err != nil {
		return err
	}
	if code != 0 {
		trim := strings.TrimSpace(string(errOut))
		if strings.Contains(trim, "No such file") || strings.Contains(trim, "Cannot stat") || strings.Contains(trim, "not found") {
			return fs.ErrNotExist
		}
		return fmt.Errorf("k8s archive read failed: exit=%d stderr=%s", code, trim)
	}

	statPayload := map[string]interface{}{
		"name":       name,
		"size":       len(out),
		"mode":       uint32(fs.ModePerm),
		"mtime":      time.Now().UTC().Format(time.RFC3339Nano),
		"linkTarget": "",
	}
	statJSON, err := json.Marshal(statPayload)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/x-tar")
	w.Header().Set("X-Docker-Container-Path-Stat", base64.StdEncoding.EncodeToString(statJSON))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	return nil
}

func untarToDir(r io.Reader, dst string) ([]string, error) {
	tr := tar.NewReader(r)
	seenTop := map[string]struct{}{}
	var topOrder []string

	addTop := func(cleanName string) {
		first := strings.Split(cleanName, "/")[0]
		if first == "" {
			return
		}
		if _, ok := seenTop[first]; ok {
			return
		}
		seenTop[first] = struct{}{}
		topOrder = append(topOrder, first)
	}

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return topOrder, nil
		}
		if err != nil {
			return nil, err
		}
		if h == nil {
			continue
		}
		rawName := strings.TrimSpace(h.Name)
		if rawName == "" || strings.Contains(rawName, "..") {
			continue
		}
		cleanName, ok := normalizeLayerPath(h.Name)
		if !ok {
			continue
		}
		addTop(cleanName)
		// Resolve target under destination with explicit relative-path containment proof.
		safeTarget, err := resolvePathUnder(dst, filepath.FromSlash(cleanName))
		if err != nil {
			continue
		}
		if err := ensurePathUnderBase(dst, safeTarget); err != nil {
			continue
		}

		switch h.Typeflag {
		case tar.TypeDir:
			// Check parent is safe before creating directory (to catch traversal via parent symlink)
			if err := isDirSafe(dst, filepath.Dir(safeTarget)); err != nil {
				continue
			}
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			if err := os.MkdirAll(safeTarget, fs.FileMode(h.Mode)); err != nil {
				return nil, err
			}
			// Verify the created directory itself resolves safely (in case it became a symlink somehow)
			if err := isDirSafe(dst, safeTarget); err != nil {
				_ = os.RemoveAll(safeTarget)
				continue
			}
		case tar.TypeReg, tar.TypeRegA:
			if _, err := ensureParentDir(dst, safeTarget); err != nil {
				continue
			}
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			_ = os.RemoveAll(safeTarget)
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			f, err := os.OpenFile(safeTarget, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(h.Mode))
			if err != nil {
				return nil, err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return nil, err
			}
			if err := f.Close(); err != nil {
				return nil, err
			}
		case tar.TypeSymlink:
			if ok, err := isSafeLinkTarget(h.Linkname, safeTarget, dst); !ok {
				// Consider logging the error for debugging: log.Printf("Skipping unsafe symlink target: %v", err)
				_ = err // Mark err as used to suppress compiler warning
				continue
			}
			if _, err := ensureParentDir(dst, safeTarget); err != nil {
				continue
			}
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			relSymlinkTarget, err := filepath.Rel(dst, safeTarget)
			if err != nil || relSymlinkTarget == ".." || strings.HasPrefix(relSymlinkTarget, ".."+string(filepath.Separator)) || filepath.IsAbs(relSymlinkTarget) {
				continue
			}
			_ = os.RemoveAll(safeTarget)
			absDst, err := filepath.Abs(dst)
			if err != nil {
				continue
			}
			absTarget, err := filepath.Abs(safeTarget)
			if err != nil {
				continue
			}
			relTarget, err := filepath.Rel(absDst, absTarget)
			if err != nil || relTarget == ".." || strings.HasPrefix(relTarget, ".."+string(filepath.Separator)) || filepath.IsAbs(relTarget) {
				continue
			}
			if err := os.Symlink(h.Linkname, absTarget); err != nil {
				return nil, err
			}
		case tar.TypeLink:
			linkName, ok := normalizeLayerPath(h.Linkname)
			if !ok {
				continue
			}
			safeLinkTarget, err := resolvePathUnder(dst, filepath.FromSlash(linkName))
			if err != nil {
				// log.Printf("Skipping potentially malicious hardlink source in archive: %v", err)
				continue
			}
			if err := ensurePathUnderBase(dst, safeLinkTarget); err != nil {
				continue
			}
			// Check if the source of the hardlink is in a safe directory
			if err := isDirSafe(dst, filepath.Dir(safeLinkTarget)); err != nil {
				continue
			}

			if _, err := ensureParentDir(dst, safeTarget); err != nil {
				continue
			}
			// Final safety check before removing: ensure safeTarget is still within dst
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			_ = os.RemoveAll(safeTarget)
			if err := ensurePathUnderBase(dst, safeTarget); err != nil {
				continue
			}
			if err := ensurePathUnderBase(dst, safeLinkTarget); err != nil {
				continue
			}
			if err := os.Link(safeLinkTarget, safeTarget); err != nil {
				return nil, err
			}
		default:
			continue
		}
	}
}
