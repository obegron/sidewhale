package main

import "testing"

func TestApplyRedisRuntimeCompatAddsBind(t *testing.T) {
	got := applyRedisRuntimeCompat([]string{"redis-server"}, "127.0.0.2")
	want := []string{"redis-server", "--bind", "127.0.0.2"}
	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("arg[%d] = %q, want %q (%v)", i, got[i], want[i], got)
		}
	}
}

func TestApplyRedisRuntimeCompatKeepsExistingBind(t *testing.T) {
	in := []string{"redis-server", "--bind", "127.0.0.9"}
	got := applyRedisRuntimeCompat(in, "127.0.0.2")
	if len(got) != len(in) {
		t.Fatalf("len(got) = %d, want %d (%v)", len(got), len(in), got)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("arg[%d] = %q, want %q (%v)", i, got[i], in[i], got)
		}
	}
}

func TestAllocateLoopbackIPSkipsUsed(t *testing.T) {
	store := &containerStore{
		containers: map[string]*Container{
			"a": {LoopbackIP: "127.0.0.2"},
			"b": {LoopbackIP: "127.0.0.3"},
		},
	}
	ip, err := store.allocateLoopbackIP()
	if err != nil {
		t.Fatalf("allocateLoopbackIP error: %v", err)
	}
	if ip != "127.0.0.4" {
		t.Fatalf("allocateLoopbackIP = %q, want %q", ip, "127.0.0.4")
	}
}

func TestApplyTiniRuntimeCompatEnvAddsSubreaper(t *testing.T) {
	got := applyTiniRuntimeCompatEnv([]string{"A=B"}, []string{"/sbin/tini", "--", "/docker-entrypoint.sh"})
	if !envHasKey(got, "TINI_SUBREAPER") {
		t.Fatalf("expected TINI_SUBREAPER in env, got %v", got)
	}
}

func TestApplyTiniRuntimeCompatEnvRespectsExistingSetting(t *testing.T) {
	in := []string{"TINI_SUBREAPER=0"}
	got := applyTiniRuntimeCompatEnv(in, []string{"/sbin/tini", "--", "cmd"})
	if len(got) != len(in) || got[0] != in[0] {
		t.Fatalf("expected env unchanged, got %v", got)
	}
}

func TestApplyLLdapRuntimeCompatEnvAddsDefaults(t *testing.T) {
	got := applyLLdapRuntimeCompatEnv([]string{"A=B"}, "127.0.0.9")
	if !envHasKey(got, "LLDAP_LDAP_HOST") || !envHasKey(got, "LLDAP_HTTP_HOST") {
		t.Fatalf("expected ldap host envs, got %v", got)
	}
}

func TestApplyLLdapRuntimeCompatEnvKeepsUserOverrides(t *testing.T) {
	in := []string{"LLDAP_LDAP_HOST=127.0.0.77", "LLDAP_HTTP_HOST=127.0.0.88"}
	got := applyLLdapRuntimeCompatEnv(in, "127.0.0.9")
	if len(got) != len(in) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(in))
	}
	if got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("expected user env preserved, got %v", got)
	}
}
