package main

import (
	"archive/tar"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
)

// isSymlinkTargetSafe checks if a symlink target (linkname) would resolve safely
// within the rootfs when created at symlinkPath.
func isSymlinkTargetSafe(linkname, symlinkPath, rootfs string) (bool, error) {
	// 1. Reject absolute link names directly.
	if filepath.IsAbs(linkname) {
		return false, fmt.Errorf("absolute symlink target '%s' is not allowed", linkname)
	}

	// 2. Resolve linkname relative to the directory where the symlink itself will be placed.
	symlinkDir := filepath.Dir(symlinkPath)
	resolvedLinkTarget := filepath.Clean(filepath.Join(symlinkDir, linkname))

	// 3. Use isPathWithinBase to check if this resolved target is within the overall rootfs.
	ok, err := isPathWithinBase(rootfs, resolvedLinkTarget)
	if err != nil {
		return false, fmt.Errorf("error checking symlink target safety: %w", err)
	}
	if !ok {
		return false, fmt.Errorf("symlink target '%s' resolves outside rootfs '%s'", linkname, rootfs)
	}

	return true, nil
}

func dirSize(root string) (int64, error) {
	var total int64
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		total += info.Size()
		return nil
	})
	return total, err
}

type dirAttributes struct {
	mode    fs.FileMode
	modTime time.Time
}

func extractLayer(rootfs string, layer v1.Layer, dirModes map[string]dirAttributes) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("layer read failed: %w", err)
	}
	defer rc.Close()

	tr := tar.NewReader(rc)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("tar read failed: %w", err)
		}
		if h == nil {
			continue
		}

		cleanName, ok := normalizeLayerPath(h.Name)
		if !ok {
			continue
		}
		targetPath, err := isPathSafe(rootfs, cleanName)
		if err != nil {
			// log.Printf("Skipping potentially malicious path in layer: %v", err)
			continue // Skip this entry
		}

		base := filepath.Base(cleanName)
		dir := filepath.Dir(cleanName)

		if strings.HasPrefix(base, ".wh.") {
			if base == ".wh..wh..opq" {
				cleanDirForRemoval, err := isPathSafe(rootfs, dir)
				if err != nil {
					// log.Printf("Skipping removal of potentially malicious directory: %v", err)
					continue
				}
				if err := removeAllChildren(cleanDirForRemoval); err != nil {
					return fmt.Errorf("whiteout opaque failed: %w", err)
				}
				continue
			}
			removeTargetRaw := filepath.Join(dir, strings.TrimPrefix(base, ".wh."))
			removeTarget, err := isPathSafe(rootfs, removeTargetRaw)
			if err != nil {
				// log.Printf("Skipping removal of potentially malicious whiteout target: %v", err)
				continue
			}
			_ = os.RemoveAll(removeTarget)
			continue
		}

		switch h.Typeflag {
		case tar.TypeDir:
			// Check parent is safe before creating
			if err := isDirSafe(rootfs, filepath.Dir(targetPath)); err != nil {
				continue
			}
			if err := os.MkdirAll(targetPath, 0o755); err != nil {
				return fmt.Errorf("mkdir failed: %w", err)
			}
			// Verify the created directory itself resolves safely
			if err := isDirSafe(rootfs, targetPath); err != nil {
				_ = os.RemoveAll(targetPath)
				continue
			}
			dirModes[targetPath] = dirAttributes{mode: fs.FileMode(h.Mode), modTime: h.ModTime}
		case tar.TypeReg, tar.TypeRegA:
			safeParentTarget, err := isPathSafe(rootfs, filepath.Dir(cleanName))
			if err != nil {
				continue
			}
			if err := isDirSafe(rootfs, safeParentTarget); err != nil {
				continue
			}
			if err := os.MkdirAll(safeParentTarget, 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			f, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(h.Mode))
			if err != nil {
				return fmt.Errorf("file create failed: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("file write failed: %w", err)
			}
			f.Close()
			_ = os.Chtimes(targetPath, time.Now(), h.ModTime)
		case tar.TypeSymlink:
			if ok, err := isSymlinkTargetSafe(h.Linkname, targetPath, rootfs); !ok {
				// Consider logging the error for debugging: log.Printf("Skipping unsafe symlink target: %v", err)
				_ = err // Mark err as used to suppress compiler warning
				continue
			}
			safeParentTarget, err := isPathSafe(rootfs, filepath.Dir(cleanName))
			if err != nil {
				continue
			}
			if err := isDirSafe(rootfs, safeParentTarget); err != nil {
				continue
			}
			if err := os.MkdirAll(safeParentTarget, 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			_ = os.RemoveAll(targetPath)
			if err := os.Symlink(h.Linkname, targetPath); err != nil {
				return fmt.Errorf("symlink failed: %w", err)
			}
		case tar.TypeLink:
			linkName, ok := normalizeLayerPath(h.Linkname)
			if !ok {
				continue
			}
			linkTarget, err := isPathSafe(rootfs, linkName)
			if err != nil {
				// log.Printf("Skipping potentially malicious hardlink target: %v", err)
				continue
			}
			if err := isDirSafe(rootfs, filepath.Dir(linkTarget)); err != nil {
				continue
			}
			safeParentTarget, err := isPathSafe(rootfs, filepath.Dir(cleanName))
			if err != nil {
				continue
			}
			if err := isDirSafe(rootfs, safeParentTarget); err != nil {
				continue
			}
			if err := os.MkdirAll(safeParentTarget, 0o755); err != nil {
				return fmt.Errorf("parent mkdir failed: %w", err)
			}
			_ = os.RemoveAll(targetPath)

			if err := os.Link(linkTarget, targetPath); err != nil {
				src, openErr := os.Open(linkTarget)
				if openErr != nil {
					return fmt.Errorf("hardlink source missing: %w", err)
				}
				dst, createErr := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
				if createErr != nil {
					src.Close()
					return fmt.Errorf("hardlink fallback create failed: %w", createErr)
				}
				if _, copyErr := io.Copy(dst, src); copyErr != nil {
					dst.Close()
					src.Close()
					return fmt.Errorf("hardlink fallback copy failed: %w", copyErr)
				}
				dst.Close()
				src.Close()
			}
		default:
			continue
		}
	}
}

func applyDirModes(dirModes map[string]dirAttributes) error {
	paths := make([]string, 0, len(dirModes))
	for path := range dirModes {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		return strings.Count(paths[i], string(os.PathSeparator)) > strings.Count(paths[j], string(os.PathSeparator))
	})
	for _, path := range paths {
		attr := dirModes[path]
		if err := os.Chmod(path, attr.mode); err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			return fmt.Errorf("dir chmod failed: %w", err)
		}
		_ = os.Chtimes(path, time.Now(), attr.modTime)
	}
	return nil
}

func normalizeLayerPath(name string) (string, bool) {
	raw := strings.TrimSpace(name)
	if raw == "" {
		return "", false
	}
	// "Zip Slip" remediation: Explicitly reject any path containing ".." components.
	// While path.Clean handles this lexically, CodeQL and strict security practices
	// prefer explicit rejection of malicious patterns in archive paths.
	if strings.Contains(raw, "..") {
		parts := strings.Split(raw, "/")
		for _, part := range parts {
			if part == ".." {
				return "", false
			}
		}
		// Also check backslash for Windows-style paths if they sneak in
		if strings.Contains(raw, "\\") {
			partsBack := strings.Split(raw, "\\")
			for _, part := range partsBack {
				if part == ".." {
					return "", false
				}
			}
		}
	}

	cleanRaw := path.Clean(raw)
	if cleanRaw == "." || cleanRaw == ".." || strings.HasPrefix(cleanRaw, "../") {
		return "", false
	}
	clean := path.Clean("/" + raw)
	rel := strings.TrimPrefix(clean, "/")
	if rel == "" || rel == "." || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", false
	}
	return rel, true
}

func removeAllChildren(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		_ = os.RemoveAll(filepath.Join(dir, entry.Name()))
	}
	return nil
}
