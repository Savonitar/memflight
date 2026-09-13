// Package schema defines the numeric observations accepted by incident schema 1.
// The collector, offline validator, and analyzer share these names; arbitrary
// input keys must not become report fields or diagnostic text.
package schema

import "sort"

var metrics, pressures, events, unlimited = buildKeys()

func buildKeys() (map[string]bool, map[string]bool, map[string]bool, map[string]bool) {
	m, p, e, u := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, name := range []string{"current", "peak", "min", "low", "high", "max", "swap.current", "swap.peak", "swap.max"} {
		m["cgroup.memory."+name] = true
	}
	for _, name := range []string{"anon", "file", "kernel", "kernel_stack", "pagetables", "percpu", "sock", "shmem", "file_mapped", "file_dirty", "inactive_anon", "active_anon", "inactive_file", "active_file", "slab", "slab_reclaimable", "slab_unreclaimable"} {
		m["cgroup.memory.stat."+name] = true
	}
	for _, scope := range []string{"cgroup.memory.events.", "cgroup.memory.events.local."} {
		for _, name := range []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} {
			m[scope+name], e[scope+name] = true, true
		}
	}
	for _, scope := range []string{"some", "full"} {
		prefix := "cgroup.memory.pressure." + scope + "."
		m[prefix+"total"] = true
		for _, name := range []string{"avg10", "avg60", "avg300"} {
			p[prefix+name] = true
		}
	}
	for _, name := range []string{"VmRSS", "RssAnon", "RssFile", "RssShmem", "VmSwap", "VmSize", "Threads"} {
		m["proc.status."+name] = true
	}
	for _, name := range []string{"Rss", "Pss", "Private_Clean", "Private_Dirty", "Shared_Clean", "Shared_Dirty", "Anonymous", "Swap"} {
		m["proc.smaps."+name] = true
	}
	m["proc.fd_count"] = true
	for _, name := range []string{"cgroup.memory.high", "cgroup.memory.max", "cgroup.memory.swap.max"} {
		u[name] = true
	}
	return m, p, e, u
}

// MetricKeys returns a sorted, independent slice of integer observation keys.
// PSI averages use IsPressure and are deliberately not included here.
func MetricKeys() []string {
	keys := make([]string, 0, len(metrics))
	for key := range metrics {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func IsMetric(key string) bool    { return metrics[key] }
func IsPressure(key string) bool  { return pressures[key] }
func IsEvent(key string) bool     { return events[key] }
func IsUnlimited(key string) bool { return unlimited[key] }
