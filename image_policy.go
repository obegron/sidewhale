package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"gopkg.in/yaml.v3"
)

func loadAllowedImagePrefixes(flagList string, flagFile string) ([]string, error) {
	rawList := strings.TrimSpace(flagList)
	if rawList == "" {
		rawList = strings.TrimSpace(os.Getenv("TCEXECUTOR_ALLOWED_IMAGES"))
	}
	filePath := strings.TrimSpace(flagFile)
	if filePath == "" {
		filePath = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_POLICY_FILE"))
	}

	prefixes := splitCSV(rawList)
	if filePath != "" {
		filePrefixes, err := readImagePolicyFile(filePath)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, filePrefixes...)
	}
	return normalizeUniquePrefixes(prefixes), nil
}

func loadImageMirrorRules(flagList string, flagFile string) ([]imageMirrorRule, error) {
	rawList := strings.TrimSpace(flagList)
	if rawList == "" {
		rawList = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_MIRRORS"))
	}
	filePath := strings.TrimSpace(flagFile)
	if filePath == "" {
		filePath = strings.TrimSpace(os.Getenv("TCEXECUTOR_IMAGE_MIRROR_FILE"))
	}

	rules := parseMirrorCSV(rawList)
	if filePath != "" {
		fileRules, err := readImageMirrorFile(filePath)
		if err != nil {
			return nil, err
		}
		rules = append(rules, fileRules...)
	}
	return normalizeMirrorRules(rules), nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func parseMirrorCSV(raw string) []imageMirrorRule {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]imageMirrorRule, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		from, to, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out = append(out, imageMirrorRule{FromPrefix: from, ToPrefix: to})
	}
	return out
}

func readImageMirrorFile(path string) ([]imageMirrorRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image mirror file: %w", err)
	}
	var asList []imageMirrorRule
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 {
		return asList, nil
	}
	var cfg imageMirrorFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse image mirror file: %w", err)
	}
	merged := append([]imageMirrorRule{}, cfg.ImageMirrors...)
	merged = append(merged, cfg.Mirrors...)
	return merged, nil
}

func normalizeMirrorRules(in []imageMirrorRule) []imageMirrorRule {
	out := make([]imageMirrorRule, 0, len(in))
	seen := map[string]struct{}{}
	for _, rule := range in {
		from := normalizeImageToken(rule.FromPrefix)
		to := normalizeImageToken(rule.ToPrefix)
		if from == "" || to == "" {
			continue
		}
		key := from + "=>" + to
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, imageMirrorRule{FromPrefix: from, ToPrefix: to})
	}
	return out
}

func readImagePolicyFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read image policy file: %w", err)
	}
	var asList []string
	if err := yaml.Unmarshal(data, &asList); err == nil && len(asList) > 0 {
		return asList, nil
	}
	var cfg imagePolicyFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse image policy file: %w", err)
	}
	merged := append([]string{}, cfg.AllowedImages...)
	merged = append(merged, cfg.AllowedImagePrefixes...)
	merged = append(merged, cfg.Images...)
	return merged, nil
}

func normalizeUniquePrefixes(prefixes []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		p := normalizeImageToken(prefix)
		if p == "" {
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

func isImageAllowed(ref string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, candidate := range imageMatchCandidates(ref) {
		for _, prefix := range prefixes {
			if strings.HasPrefix(candidate, prefix) {
				return true
			}
		}
	}
	return false
}

func rewriteImageReference(ref string, rules []imageMirrorRule) string {
	ref = normalizeImageToken(ref)
	if ref == "" || len(rules) == 0 {
		return ref
	}
	candidates := orderedImageCandidates(ref, false)
	for _, rule := range rules {
		for _, candidate := range candidates {
			if strings.HasPrefix(candidate, rule.FromPrefix) {
				return rule.ToPrefix + strings.TrimPrefix(candidate, rule.FromPrefix)
			}
		}
	}
	return ref
}

func imageMatchCandidates(ref string) []string {
	return orderedImageCandidates(ref, true)
}

func orderedImageCandidates(ref string, includeContext bool) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, 6)
	add := func(s string) {
		s = normalizeImageToken(s)
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
		for _, alias := range dockerHubAliases(s) {
			if _, ok := seen[alias]; ok {
				continue
			}
			seen[alias] = struct{}{}
			out = append(out, alias)
		}
	}
	add(ref)
	if parsed, err := name.ParseReference(strings.TrimSpace(ref)); err == nil {
		add(parsed.Name())
		if includeContext {
			add(parsed.Context().Name())
		}
	}
	return out
}

func normalizeImageToken(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

func imageRefHasTag(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	slash := strings.LastIndex(ref, "/")
	colon := strings.LastIndex(ref, ":")
	return colon > slash
}

func dockerHubAliases(s string) []string {
	s = normalizeImageToken(s)
	if s == "" {
		return nil
	}
	const dockerIO = "docker.io/"
	const indexDockerIO = "index.docker.io/"
	switch {
	case strings.HasPrefix(s, dockerIO):
		return []string{indexDockerIO + strings.TrimPrefix(s, dockerIO)}
	case strings.HasPrefix(s, indexDockerIO):
		return []string{dockerIO + strings.TrimPrefix(s, indexDockerIO)}
	default:
		return nil
	}
}
