package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

func applyRedisRuntimeCompat(cmdArgs []string, loopbackIP string) []string {
	if len(cmdArgs) == 0 || strings.TrimSpace(loopbackIP) == "" {
		return cmdArgs
	}
	if hasArg(cmdArgs, "--bind") {
		return cmdArgs
	}
	out := append([]string{}, cmdArgs...)
	out = append(out, "--bind", loopbackIP)
	return out
}

func hasArg(args []string, needle string) bool {
	for _, arg := range args {
		if arg == needle {
			return true
		}
	}
	return false
}

func applyTiniRuntimeCompatEnv(env, cmdArgs []string) []string {
	if !usesTini(cmdArgs) || hasArg(cmdArgs, "-s") || envHasKey(env, "TINI_SUBREAPER") {
		return env
	}
	out := append([]string{}, env...)
	out = append(out, "TINI_SUBREAPER=1")
	return out
}

func applyLLdapRuntimeCompatEnv(env []string, loopbackIP string) []string {
	ip := strings.TrimSpace(loopbackIP)
	if ip == "" {
		return env
	}
	defaults := []string{
		"LLDAP_LDAP_HOST=" + ip,
		"LLDAP_HTTP_HOST=" + ip,
	}
	return mergeEnv(defaults, env)
}

func applySSHDRuntimeCompat(cmdArgs []string, loopbackIP string, port int) []string {
	ip := strings.TrimSpace(loopbackIP)
	if len(cmdArgs) == 0 || ip == "" || port <= 0 {
		return cmdArgs
	}
	if hasArg(cmdArgs, "-p") {
		return cmdArgs
	}
	portArg := strconv.Itoa(port)
	listenArg := "ListenAddress=" + ip
	if len(cmdArgs) >= 3 {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(cmdArgs[0])))
		if (base == "sh" || base == "bash") && cmdArgs[1] == "-c" {
			script := cmdArgs[2]
			lowerScript := strings.ToLower(script)
			if strings.Contains(lowerScript, "sshd") {
				if strings.Contains(script, " -p ") {
					return cmdArgs
				}
				out := append([]string{}, cmdArgs...)
				rewritten := script
				if !strings.Contains(rewritten, " -e ") && !strings.HasSuffix(rewritten, " -e") {
					rewritten += " -e"
				}
				rewritten += " -o " + listenArg + " -p " + portArg
				out[2] = rewritten
				return out
			}
		}
	}
	for _, arg := range cmdArgs {
		if strings.Contains(strings.ToLower(arg), "sshd") {
			out := append([]string{}, cmdArgs...)
			if !hasArg(out, "-e") {
				out = append(out, "-e")
			}
			out = append(out, "-o", listenArg, "-p", portArg)
			return out
		}
	}
	return cmdArgs
}

func applyNginxRuntimeCompatRootfs(rootfs string, listenPort int) error {
	if strings.TrimSpace(rootfs) == "" || listenPort <= 0 {
		return nil
	}
	paths := []string{
		filepath.Join(rootfs, "etc", "nginx", "conf.d", "default.conf"),
		filepath.Join(rootfs, "etc", "nginx", "http.d", "default.conf"),
		filepath.Join(rootfs, "etc", "nginx", "nginx.conf"),
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return err
		}
		rewritten := rewriteNginxListenConfig(string(b), listenPort)
		if rewritten == string(b) {
			continue
		}
		if err := os.WriteFile(p, []byte(rewritten), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func rewriteNginxListenConfig(conf string, listenPort int) string {
	if listenPort <= 0 {
		return conf
	}
	port := strconv.Itoa(listenPort)
	re := regexp.MustCompile(`(?m)^(\s*listen\s+)(\[::\]:)?80(\s+default_server)?;`)
	return re.ReplaceAllString(conf, "${1}${2}"+port+"${3};")
}

func writeNginxCompatConfig(rootfs string, listenPort int) error {
	if strings.TrimSpace(rootfs) == "" || listenPort <= 0 {
		return nil
	}
	p := filepath.Join(rootfs, "etc", "nginx", "nginx-sidewhale.conf")
	content := fmt.Sprintf(`worker_processes auto;
error_log /dev/stderr notice;
pid /tmp/nginx.pid;
events {
  worker_connections 1024;
}
http {
  include /etc/nginx/mime.types;
  default_type application/octet-stream;
  access_log /dev/stdout;
  sendfile on;
  keepalive_timeout 65;
  server {
    listen %d;
    listen [::]:%d;
    server_name localhost;
    location / {
      root /usr/share/nginx/html;
      index index.html index.htm;
    }
  }
}
`, listenPort, listenPort)
	return os.WriteFile(p, []byte(content), 0o644)
}

func applyNginxRuntimeCompatCommand(cmdArgs []string, listenPort int) []string {
	if listenPort <= 0 {
		return cmdArgs
	}
	return []string{
		"nginx",
		"-g",
		"daemon off;",
		"-c",
		"/etc/nginx/nginx-sidewhale.conf",
	}
}

func usesTini(cmdArgs []string) bool {
	for _, arg := range cmdArgs {
		base := strings.ToLower(filepath.Base(strings.TrimSpace(arg)))
		if base == "tini" || base == "tini-static" {
			return true
		}
	}
	return false
}
