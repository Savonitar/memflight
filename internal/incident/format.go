// Package incident stores versioned, bounded recordings. Collection models stay
// separate from the on-disk JSON schema.
package incident

import (
	"time"

	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/recorder"
)

const SchemaVersion = 1

type Config struct {
	Interval         time.Duration       `json:"interval_ns"`
	ElevatedInterval time.Duration       `json:"elevated_interval_ns"`
	SyncInterval     time.Duration       `json:"sync_interval_ns"`
	MaxBytes         int64               `json:"max_bytes_total"`
	Retention        int                 `json:"retention_including_active"`
	Thresholds       recorder.Thresholds `json:"thresholds"`
}

type Target struct {
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
	CgroupID   string `json:"cgroup_id,omitempty"`
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	AgentVersion  string     `json:"agent_version"`
	StartedAt     time.Time  `json:"started_at"`
	EndedAt       *time.Time `json:"ended_at,omitempty"`
	RecoveredAt   *time.Time `json:"recovered_at,omitempty"`
	Closed        bool       `json:"closed"`
	Termination   string     `json:"termination"`
	Target        Target     `json:"target"`
	CgroupVersion int        `json:"cgroup_version"`
	Config        Config     `json:"config"`
	Capabilities  []string   `json:"capabilities"`
	Warnings      []string   `json:"warnings"`
}

type sampleRecord struct {
	Time      time.Time          `json:"time"`
	ElapsedNS int64              `json:"elapsed_ns"`
	Target    Target             `json:"target"`
	Present   *bool              `json:"present,omitempty"`
	Metrics   map[string]uint64  `json:"metrics"`
	Pressure  map[string]float64 `json:"pressure,omitempty"`
	Unlimited []string           `json:"unlimited,omitempty"`
	Warnings  []string           `json:"warnings,omitempty"`
	State     string             `json:"state"`
	Events    map[string]uint64  `json:"events,omitempty"`
}

func target(t model.Identity) Target { return Target{t.PID, t.StartTicks, t.CgroupID} }
func record(s model.Sample) sampleRecord {
	return sampleRecord{s.Time.UTC(), s.ElapsedNS, target(s.Target), s.Present, s.Metrics, s.Pressure, s.Unlimited, s.Warnings, s.State, s.Events}
}
func (s sampleRecord) model() model.Sample {
	return model.Sample{Time: s.Time, ElapsedNS: s.ElapsedNS, Target: model.Identity{PID: s.Target.PID, StartTicks: s.Target.StartTicks, CgroupID: s.Target.CgroupID}, Present: s.Present, Metrics: s.Metrics, Pressure: s.Pressure, Unlimited: s.Unlimited, Warnings: s.Warnings, State: s.State, Events: s.Events}
}
