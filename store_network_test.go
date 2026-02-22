package main

import "testing"

func TestSelfHostAliasesForContainer(t *testing.T) {
	store := &containerStore{
		networks: map[string]*Network{
			"bridge": {
				ID:   "bridge",
				Name: "bridge",
				Containers: map[string]*NetworkEndpoint{
					"abc123": {
						Name:    "kafka-upstream-shape-it",
						Aliases: []string{"kafka", ""},
					},
				},
			},
		},
	}

	got := store.selfHostAliasesForContainer("abc123")
	if len(got) != 2 {
		t.Fatalf("len(got) = %d, want 2 (%v)", len(got), got)
	}
	if got["kafka"] != "127.0.0.1" {
		t.Fatalf("kafka ip = %q, want 127.0.0.1", got["kafka"])
	}
	if got["kafka-upstream-shape-it"] != "127.0.0.1" {
		t.Fatalf("name ip = %q, want 127.0.0.1", got["kafka-upstream-shape-it"])
	}
}
