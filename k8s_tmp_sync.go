package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func syncContainerTmpToK8sPod(ctx context.Context, client *k8sClient, c *Container) error {
	if client == nil || c == nil || strings.TrimSpace(c.K8sPodName) == "" {
		return nil
	}
	srcRoot := containerTmpDir(c)
	if strings.TrimSpace(srcRoot) == "" {
		return nil
	}
	if _, err := os.Stat(srcRoot); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(srcRoot, func(srcPath string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcRoot, srcPath)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		dstPath := filepath.Clean("/tmp/" + rel)

		if d.IsDir() {
			cmd := []string{"sh", "-lc", "mkdir -p " + shellQuote(dstPath)}
			_, stderr, exitCode, err := client.execPod(ctx, c.K8sNamespace, c.K8sPodName, cmd)
			if err != nil {
				return err
			}
			if exitCode != 0 {
				return fmt.Errorf("sync tmp mkdir failed path=%s exit=%d stderr=%s", dstPath, exitCode, strings.TrimSpace(string(stderr)))
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		data, err := os.ReadFile(srcPath)
		if err != nil {
			return err
		}
		mode := info.Mode().Perm()
		cmdStr := strings.Join([]string{
			"mkdir -p " + shellQuote(filepath.Dir(dstPath)),
			"printf %s " + shellQuote(string(data)) + " > " + shellQuote(dstPath),
			fmt.Sprintf("chmod %o %s", mode, shellQuote(dstPath)),
		}, " && ")
		cmd := []string{"sh", "-lc", cmdStr}
		_, stderr, exitCode, err := client.execPod(ctx, c.K8sNamespace, c.K8sPodName, cmd)
		if err != nil {
			return err
		}
		if exitCode != 0 {
			return fmt.Errorf("sync tmp file failed path=%s exit=%d stderr=%s", dstPath, exitCode, strings.TrimSpace(string(stderr)))
		}
		return nil
	})
}
