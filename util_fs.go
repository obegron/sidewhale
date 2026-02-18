package main

import (
	"archive/tar"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// isPathWithinBase checks if a given fullPath is contained within basePath.
// It resolves both paths to absolute paths for a robust comparison.
func isPathWithinBase(basePath, fullPath string) (bool, error) {
	absBasePath, err := filepath.Abs(basePath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path for base: %w", err)
	}
	absFullPath, err := filepath.Abs(fullPath)
	if err != nil {
		return false, fmt.Errorf("failed to get absolute path for fullPath: %w", err)
	}

	rel, err := filepath.Rel(absBasePath, absFullPath)
	if err != nil {
		return false, err
	}
	// If the relative path starts with ".." it means it's outside.
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return false, nil
	}
	return true, nil
}

// isPathSafe joins basePath and targetPath, then checks if the resulting path is within basePath.
// It returns the cleaned joined path or an error if path traversal is detected.
func isPathSafe(basePath, targetPath string) (string, error) {
	joinedPath := filepath.Clean(filepath.Join(basePath, targetPath))
	ok, err := isPathWithinBase(basePath, joinedPath)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("path traversal attempt detected: '%s' resolves outside base directory '%s'", targetPath, basePath)
	}
	return joinedPath, nil
}

// isDirSafe checks if the directory at dirPath (or its deepest existing ancestor)
// is contained within the allowed basePath. This guards against writing through
// symlinks that point outside the sandbox.
func isDirSafe(basePath, dirPath string) error {
	current := dirPath
	for {
		_, err := os.Lstat(current)
		if err == nil {
			// Path exists, check where it resolves
			resolved, err := filepath.EvalSymlinks(current)
			if err != nil {
				return err
			}
			ok, err := isPathWithinBase(basePath, resolved)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("path '%s' resolves to '%s' which is outside base '%s'", current, resolved, basePath)
			}
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
		// Current path doesn't exist, check parent
		parent := filepath.Dir(current)
		if parent == current || parent == "." || parent == string(filepath.Separator) {
			// We reached root or cannot go further up
			break
		}
		current = parent
	}
	return nil
}

func copyDirContents(srcDir, dstDir string) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return err
	}
	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		// Sanitize the destination path using isPathSafe
		dst, err := isPathSafe(dstDir, entry.Name())
		if err != nil {
			// log.Printf("Skipping potentially malicious path during copy: %v", err)
			continue // Skip this entry
		}
		if err := copyFSNode(src, dst); err != nil {
			return err
		}
	}
	return nil
}

func copyFSNode(src, dst string) error {
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(src)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		return os.Symlink(link, dst)
	case info.IsDir():
		if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childSrc := filepath.Join(src, entry.Name())
			// Sanitize the destination path for recursive call
			childDst, err := isPathSafe(dst, entry.Name())
			if err != nil {
				// log.Printf("Skipping potentially malicious path during recursive copy: %v", err)
				continue // Skip this entry
			}
			if err := copyFSNode(childSrc, childDst); err != nil {
				return err
			}
		}
		return os.Chmod(dst, info.Mode().Perm())
	case info.Mode().IsRegular():
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		_ = os.RemoveAll(dst)
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			in.Close()
			return err
		}
		_, copyErr := io.Copy(out, in)
		closeErr := out.Close()
		in.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		return os.Chmod(dst, info.Mode().Perm())
	default:
		return nil
	}
}

func writePathToTar(tw *tar.Writer, sourcePath, nameInTar string) error {
	info, err := os.Lstat(sourcePath)
	if err != nil {
		return err
	}

	nameInTar = strings.TrimPrefix(path.Clean("/"+filepath.ToSlash(nameInTar)), "/")
	if nameInTar == "." || nameInTar == "" {
		nameInTar = filepath.Base(sourcePath)
	}

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		link, err := os.Readlink(sourcePath)
		if err != nil {
			return err
		}
		h, err := tar.FileInfoHeader(info, link)
		if err != nil {
			return err
		}
		h.Name = nameInTar
		return tw.WriteHeader(h)
	case info.IsDir():
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = nameInTar + "/"
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		entries, err := os.ReadDir(sourcePath)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			childSrc := filepath.Join(sourcePath, entry.Name())
			childTar := path.Join(nameInTar, entry.Name())
			if err := writePathToTar(tw, childSrc, childTar); err != nil {
				return err
			}
		}
		return nil
	case info.Mode().IsRegular():
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name = nameInTar
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		f, err := os.Open(sourcePath)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		closeErr := f.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	default:
		return nil
	}
}

func copyDir(src, dst string) error {
	type copiedDir struct {
		path    string
		mode    fs.FileMode
		modTime time.Time
	}
	var dirs []copiedDir

	if err := filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		target := filepath.Join(dst, rel)
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
			dirs = append(dirs, copiedDir{path: target, mode: info.Mode(), modTime: info.ModTime()})
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, err := os.Readlink(path)
			if err != nil {
				return err
			}
			_ = os.RemoveAll(target)
			return os.Symlink(link, target)
		}
		if info.Mode().IsRegular() {
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			_ = os.RemoveAll(target)
			if err := os.Link(path, target); err != nil {
				srcFile, openErr := os.Open(path)
				if openErr != nil {
					return openErr
				}
				copyErr := func() error {
					defer srcFile.Close()
					dstFile, createErr := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
					if createErr != nil {
						return createErr
					}
					defer dstFile.Close()
					_, ioErr := io.Copy(dstFile, srcFile)
					return ioErr
				}()
				if copyErr != nil {
					return copyErr
				}
			}
			_ = os.Chtimes(target, time.Now(), info.ModTime())
		}
		return nil
	}); err != nil {
		return err
	}

	sort.Slice(dirs, func(i, j int) bool {
		return strings.Count(dirs[i].path, string(os.PathSeparator)) > strings.Count(dirs[j].path, string(os.PathSeparator))
	})
	for _, d := range dirs {
		if err := os.Chmod(d.path, d.mode.Perm()); err != nil {
			return err
		}
		_ = os.Chtimes(d.path, time.Now(), d.modTime)
	}
	return nil
}

func randomID(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Message: msg})
}
