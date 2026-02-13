package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func resolveProotIdentity(rootfs, userSpec string) (string, bool) {
	spec := strings.TrimSpace(userSpec)
	if spec == "" {
		return "0:0", true
	}

	userPart := spec
	groupPart := ""
	if i := strings.Index(spec, ":"); i >= 0 {
		userPart = spec[:i]
		groupPart = spec[i+1:]
	}

	uid, defaultGID, ok := resolveUserToken(rootfs, userPart)
	if !ok {
		return "", false
	}
	gid := defaultGID
	if strings.TrimSpace(groupPart) != "" {
		groupID, gok := resolveGroupToken(rootfs, groupPart)
		if !gok {
			return "", false
		}
		gid = groupID
	}
	if gid == "" {
		gid = uid
	}
	return uid + ":" + gid, true
}

func ensureSyntheticUserIdentity(rootfs, userSpec string) error {
	spec := strings.TrimSpace(userSpec)
	if spec == "" {
		return nil
	}
	userPart := spec
	groupPart := ""
	if i := strings.Index(spec, ":"); i >= 0 {
		userPart = spec[:i]
		groupPart = spec[i+1:]
	}
	userPart = strings.TrimSpace(userPart)
	groupPart = strings.TrimSpace(groupPart)
	if !isDigits(userPart) {
		return nil
	}

	uid := userPart
	gid := uid
	if groupPart != "" {
		if isDigits(groupPart) {
			gid = groupPart
		} else if resolved, ok := lookupGroupByName(rootfs, groupPart); ok {
			gid = resolved
		}
	} else if resolved, ok := lookupGIDForUID(rootfs, uid); ok {
		gid = resolved
	}

	if _, found := lookupGIDForUID(rootfs, uid); !found {
		passwdLine := fmt.Sprintf("sidewhale-%s:x:%s:%s:sidewhale synthetic user:/tmp:/sbin/nologin", uid, uid, gid)
		if err := appendUniqueLine(filepath.Join(rootfs, "etc", "passwd"), passwdLine); err != nil {
			return fmt.Errorf("passwd synthetic user setup failed: %w", err)
		}
	}
	if !groupExistsByGID(rootfs, gid) {
		groupLine := fmt.Sprintf("sidewhale-%s:x:%s:", gid, gid)
		if err := appendUniqueLine(filepath.Join(rootfs, "etc", "group"), groupLine); err != nil {
			return fmt.Errorf("group synthetic user setup failed: %w", err)
		}
	}
	return nil
}

func appendUniqueLine(filePath, line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return err
	}
	data, err := os.ReadFile(filePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for _, existing := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(existing) == line {
			return nil
		}
	}
	content := strings.TrimRight(string(data), "\n")
	if content == "" {
		content = line + "\n"
	} else {
		content = content + "\n" + line + "\n"
	}
	return os.WriteFile(filePath, []byte(content), 0o644)
}

func resolveUserToken(rootfs, token string) (uid, gid string, ok bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", "", false
	}
	if isDigits(t) {
		if gid, found := lookupGIDForUID(rootfs, t); found {
			return t, gid, true
		}
		return t, t, true
	}
	return lookupUserByName(rootfs, t)
}

func resolveGroupToken(rootfs, token string) (string, bool) {
	t := strings.TrimSpace(token)
	if t == "" {
		return "", false
	}
	if isDigits(t) {
		return t, true
	}
	return lookupGroupByName(rootfs, t)
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func lookupUserByName(rootfs, name string) (uid, gid string, ok bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[0] != name {
			continue
		}
		if !isDigits(fields[2]) || !isDigits(fields[3]) {
			return "", "", false
		}
		return fields[2], fields[3], true
	}
	return "", "", false
}

func lookupGIDForUID(rootfs, uid string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "passwd"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 4 {
			continue
		}
		if fields[2] != uid {
			continue
		}
		if !isDigits(fields[3]) {
			return "", false
		}
		return fields[3], true
	}
	return "", false
}

func lookupGroupByName(rootfs, name string) (string, bool) {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		return "", false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[0] != name {
			continue
		}
		if !isDigits(fields[2]) {
			return "", false
		}
		return fields[2], true
	}
	return "", false
}

func groupExistsByGID(rootfs, gid string) bool {
	data, err := os.ReadFile(filepath.Join(rootfs, "etc", "group"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		if fields[2] == gid {
			return true
		}
	}
	return false
}
