package main

import "strings"

func mergeEnv(base, override []string) []string {
	if len(base) == 0 && len(override) == 0 {
		return nil
	}
	out := make([]string, 0, len(base)+len(override))
	seen := map[string]int{}
	for _, env := range base {
		key, _ := splitEnv(env)
		if key == "" {
			continue
		}
		seen[key] = len(out)
		out = append(out, env)
	}
	for _, env := range override {
		key, _ := splitEnv(env)
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx] = env
			continue
		}
		seen[key] = len(out)
		out = append(out, env)
	}
	return out
}

func splitEnv(env string) (string, string) {
	if env == "" {
		return "", ""
	}
	key, value, ok := strings.Cut(env, "=")
	if !ok {
		return strings.TrimSpace(env), ""
	}
	return strings.TrimSpace(key), value
}

func envHasKey(env []string, key string) bool {
	key = strings.TrimSpace(key)
	if key == "" {
		return false
	}
	for _, item := range env {
		k, _ := splitEnv(item)
		if k == key {
			return true
		}
	}
	return false
}

func ensureEnvContainsToken(env []string, key, token string) []string {
	key = strings.TrimSpace(key)
	token = strings.TrimSpace(token)
	if key == "" || token == "" {
		return env
	}
	out := append([]string{}, env...)
	for i, item := range out {
		k, v := splitEnv(item)
		if k != key {
			continue
		}
		if strings.Contains(v, token) {
			return out
		}
		v = strings.TrimSpace(v)
		if v == "" {
			out[i] = key + "=" + token
		} else {
			out[i] = key + "=" + v + " " + token
		}
		return out
	}
	return append(out, key+"="+token)
}

func deduplicateEnv(env []string) []string {
	out := make([]string, 0, len(env))
	seen := map[string]int{}
	for _, e := range env {
		key, _ := splitEnv(e)
		if key == "" {
			continue
		}
		if idx, ok := seen[key]; ok {
			out[idx] = e
			continue
		}
		seen[key] = len(out)
		out = append(out, e)
	}
	return out
}
