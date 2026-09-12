package schema

import (
	"sort"
	"testing"
)

func TestRegistryContract(t *testing.T) {
	keys := MetricKeys()
	if len(keys) != 56 || !sort.StringsAreSorted(keys) {
		t.Fatalf("unexpected metric registry: %d keys", len(keys))
	}
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] || !IsMetric(key) || IsPressure(key) {
			t.Fatalf("inconsistent key %q", key)
		}
		seen[key] = true
	}
	keys[0] = "mutated"
	if MetricKeys()[0] == "mutated" || IsMetric("mutated") {
		t.Fatal("caller mutated registry")
	}
	for _, scope := range []string{"cgroup.memory.events.", "cgroup.memory.events.local."} {
		for _, name := range []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} {
			if !IsEvent(scope+name) || !IsMetric(scope+name) {
				t.Fatalf("missing event %s%s", scope, name)
			}
		}
	}
	for _, scope := range []string{"some", "full"} {
		for _, name := range []string{"avg10", "avg60", "avg300"} {
			if !IsPressure("cgroup.memory.pressure." + scope + "." + name) {
				t.Fatal("missing PSI average")
			}
		}
	}
	for _, key := range []string{"cgroup.memory.high", "cgroup.memory.max", "cgroup.memory.swap.max"} {
		if !IsUnlimited(key) || !IsMetric(key) {
			t.Fatal("missing unlimited scalar")
		}
	}
	for _, key := range []string{"", "cgroup.memory.current", "proc.fd_count", "cgroup.memory.events.oom_kill.arbitrary"} {
		if IsUnlimited(key) || IsPressure(key) || IsEvent(key) {
			t.Fatalf("unexpected specialized key %q", key)
		}
	}
}
