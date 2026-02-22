package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func defaultContainerHostname(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

func normalizeContainerHostname(hostname string) string {
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range hostname {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-':
			b.WriteRune(r)
		case r == '_' || r == ' ':
			b.WriteByte('-')
		default:
		}
	}
	return strings.Trim(b.String(), "-")
}

func writeContainerIdentityFiles(rootfs, hostname string) error {
	return writeContainerIdentityFilesWithAliasesAndHosts(rootfs, hostname, nil, nil)
}

func writeContainerIdentityFilesWithAliases(rootfs, hostname string, aliases []string) error {
	return writeContainerIdentityFilesWithAliasesAndHosts(rootfs, hostname, aliases, nil)
}

func writeContainerIdentityFilesWithAliasesAndHosts(rootfs, hostname string, aliases, extraHosts []string) error {
	hostAliasMap := map[string]string{}
	for _, alias := range aliases {
		alias = normalizeContainerHostname(alias)
		if alias == "" {
			continue
		}
		hostAliasMap[alias] = "127.0.0.1"
	}
	return writeContainerIdentityFilesWithHostAliasesAndHosts(rootfs, hostname, hostAliasMap, extraHosts)
}

func writeContainerIdentityFilesWithHostAliasesAndHosts(rootfs, hostname string, hostAliases map[string]string, extraHosts []string) error {
	hostname = normalizeContainerHostname(hostname)
	if hostname == "" {
		return nil
	}
	etcDir := filepath.Join(rootfs, "etc")
	if err := os.MkdirAll(etcDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(etcDir, "hostname"), []byte(hostname+"\n"), 0o644); err != nil {
		return err
	}

	var content strings.Builder
	content.WriteString("127.0.0.1\tlocalhost\n")
	content.WriteString("::1\tlocalhost ip6-localhost ip6-loopback\n")
	content.WriteString("127.0.1.1\t" + hostname + "\n")
	// In proot we share host UTS hostname; add it so JVM services can resolve local host.
	if hostName, err := os.Hostname(); err == nil {
		hostName = normalizeContainerHostname(hostName)
		if hostName != "" && hostName != hostname {
			content.WriteString("127.0.1.1\t" + hostName + "\n")
		}
	}

	aliasesByIP := map[string][]string{}
	for alias, ip := range hostAliases {
		alias = normalizeContainerHostname(alias)
		ip = strings.TrimSpace(ip)
		if alias == "" || alias == hostname || ip == "" {
			continue
		}
		aliasesByIP[ip] = append(aliasesByIP[ip], alias)
	}
	if len(aliasesByIP) > 0 {
		ips := make([]string, 0, len(aliasesByIP))
		for ip := range aliasesByIP {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			names := aliasesByIP[ip]
			sort.Strings(names)
			for _, alias := range names {
				content.WriteString(ip + "\t" + alias + "\n")
			}
		}
	}
	for _, raw := range extraHosts {
		host, ip, ok := parseExtraHost(raw)
		if !ok {
			continue
		}
		content.WriteString(ip + "\t" + host + "\n")
	}
	hostsPath := filepath.Join(etcDir, "hosts")
	return os.WriteFile(hostsPath, []byte(content.String()), 0o644)
}

func parseExtraHost(raw string) (host, ip string, ok bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", false
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		parts = strings.SplitN(s, "=", 2)
		if len(parts) != 2 {
			return "", "", false
		}
	}
	host = normalizeContainerHostname(parts[0])
	ip = strings.TrimSpace(parts[1])
	if host == "" || ip == "" {
		return "", "", false
	}
	return host, ip, true
}

func normalizeExtraHosts(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		host, ip, ok := parseExtraHost(raw)
		if !ok {
			continue
		}
		key := host + "=" + ip
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, host+":"+ip)
	}
	return out
}

func containerRuntimeImage(c *Container) string {
	if c == nil {
		return ""
	}
	image := strings.TrimSpace(c.ResolvedImage)
	if image == "" {
		image = strings.TrimSpace(c.Image)
	}
	return image
}

func containerEntrypointAndArgs(c *Container) ([]string, []string) {
	if c == nil {
		return nil, nil
	}
	entrypoint := append([]string{}, c.Entrypoint...)
	args := append([]string{}, c.Args...)
	if len(entrypoint) == 0 && len(args) == 0 {
		// Backward compatibility for containers created before Entrypoint/Args
		// fields existed. Prefer preserving image ENTRYPOINT semantics by
		// treating legacy Cmd as args.
		args = append([]string{}, c.Cmd...)
	}
	return entrypoint, args
}

func k8sEnvFromContainerEnv(env []string) []map[string]string {
	out := make([]map[string]string, 0, len(env))
	for _, item := range env {
		key, val, ok := strings.Cut(item, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		out = append(out, map[string]string{
			"name":  key,
			"value": val,
		})
	}
	return out
}

func ensureK8sEnvValue(env []map[string]string, key, value string) []map[string]string {
	key = strings.TrimSpace(key)
	if key == "" {
		return env
	}
	for _, item := range env {
		if strings.EqualFold(strings.TrimSpace(item["name"]), key) {
			return env
		}
	}
	return append(env, map[string]string{
		"name":  key,
		"value": value,
	})
}

func buildK8sHostAliases(hostAliasMap map[string]string) []map[string]interface{} {
	if len(hostAliasMap) == 0 {
		return nil
	}
	grouped := map[string][]string{}
	for host, ip := range hostAliasMap {
		host = strings.ToLower(normalizeContainerHostname(host))
		ip = strings.TrimSpace(ip)
		if host == "" || ip == "" {
			continue
		}
		grouped[ip] = append(grouped[ip], host)
	}
	if len(grouped) == 0 {
		return nil
	}
	ips := make([]string, 0, len(grouped))
	for ip := range grouped {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	hostAliases := make([]map[string]interface{}, 0, len(ips))
	for _, ip := range ips {
		names := grouped[ip]
		sort.Strings(names)
		hostAliases = append(hostAliases, map[string]interface{}{
			"ip":        ip,
			"hostnames": names,
		})
	}
	return hostAliases
}

func mergeContainerHostAliases(base map[string]string, extraHosts []string) map[string]string {
	if len(base) == 0 && len(extraHosts) == 0 {
		return nil
	}
	out := make(map[string]string, len(base)+len(extraHosts))
	for host, ip := range base {
		out[host] = ip
	}
	for _, raw := range extraHosts {
		host, ip, ok := parseExtraHost(raw)
		if !ok {
			continue
		}
		out[host] = ip
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func kafkaListenerHostAliases(c *Container) map[string]string {
	if c == nil {
		return nil
	}
	image := containerRuntimeImage(c)
	token := strings.ToLower(normalizeImageToken(image))
	if !strings.Contains(token, "apache/kafka") && !strings.Contains(token, "confluentinc/cp-kafka") {
		return nil
	}
	listeners := ""
	for _, raw := range c.Env {
		key, val, ok := strings.Cut(raw, "=")
		if !ok {
			continue
		}
		if strings.TrimSpace(key) == "KAFKA_LISTENERS" {
			listeners = val
			break
		}
	}
	if listeners == "" {
		return nil
	}
	out := map[string]string{}
	for _, item := range strings.Split(listeners, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		_, rhs, ok := strings.Cut(item, "://")
		if !ok {
			continue
		}
		host, _, ok := strings.Cut(rhs, ":")
		if !ok {
			continue
		}
		host = strings.ToLower(normalizeContainerHostname(host))
		if host == "" || host == "localhost" || strings.HasPrefix(host, "127.") || host == "0.0.0.0" {
			continue
		}
		out[host] = "127.0.0.1"
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ensureContainerLoopbackIP(store *containerStore, c *Container) (string, error) {
	if store == nil || c == nil {
		return "", nil
	}
	if strings.TrimSpace(c.LoopbackIP) != "" {
		return c.LoopbackIP, nil
	}
	ip, err := store.allocateLoopbackIP()
	if err != nil {
		return "", err
	}
	c.LoopbackIP = ip
	return ip, nil
}

func hostsFileHasHostname(data []byte, hostname string) bool {
	target := strings.TrimSpace(hostname)
	if target == "" {
		return true
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		for _, field := range fields[1:] {
			if field == target {
				return true
			}
		}
	}
	return false
}
