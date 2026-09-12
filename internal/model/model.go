// Package model defines the collector's in-memory observations.
package model

import "time"

// Identity prevents unrelated process lifetimes from sharing a history.
// CgroupID is an opaque identifier, never a host filesystem path.
type Identity struct {
	PID        int
	StartTicks uint64
	CgroupID   string
}

// Sample contains only allowlisted numeric kernel observations. Missing values
// are absent, never silently replaced with zero. Metrics use bytes for memory,
// counts for counters, and microseconds for PSI totals. Pressure holds PSI averages.
// Example keys: cgroup.memory.current, cgroup.memory.stat.anon,
// cgroup.memory.events.oom_kill, proc.status.RssAnon, proc.fd_count.
type Sample struct {
	Time      time.Time
	ElapsedNS int64
	Target    Identity
	Present   *bool
	Metrics   map[string]uint64
	Pressure  map[string]float64
	Unlimited []string
	Warnings  []string
	State     string
	Events    map[string]uint64
}
