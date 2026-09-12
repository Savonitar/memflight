// Package recorder implements sampling policy without performing collection or I/O.
package recorder

import (
	"fmt"
	"math"

	"github.com/Savonitar/memflight/internal/model"
)

type Thresholds struct {
	Warning    float64 `json:"warning_percent"`
	Critical   float64 `json:"critical_percent"`
	Emergency  float64 `json:"emergency_percent"`
	Hysteresis float64 `json:"hysteresis_points"`
}

func DefaultThresholds() Thresholds { return Thresholds{80, 90, 95, 5} }

func (t Thresholds) Validate() error {
	for _, v := range []float64{t.Warning, t.Critical, t.Emergency, t.Hysteresis} {
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return fmt.Errorf("thresholds must be finite")
		}
	}
	if t.Warning <= 0 || t.Warning >= t.Critical || t.Critical >= t.Emergency || t.Emergency > 100 || t.Hysteresis <= 0 || t.Hysteresis >= t.Warning {
		return fmt.Errorf("require 0 < warning < critical < emergency <= 100 and 0 < hysteresis < warning")
	}
	return nil
}

type Machine struct {
	Thresholds Thresholds
	state      string
	previous   map[string]uint64
	identity   model.Identity
}

// Observe allows direct jumps to any severity. Missing pressure never means
// recovery. Events contain counter deltas only within one process/cgroup lifetime.
func (m *Machine) Observe(s *model.Sample) (transition bool) {
	if m.identity != s.Target {
		m.state = ""
		m.previous = nil
		m.identity = s.Target
	}
	old := m.state
	current, hasCurrent := s.Metrics["cgroup.memory.current"]
	limit, hasLimit := s.Metrics["cgroup.memory.max"]
	if !hasCurrent || !hasLimit || limit == 0 {
		m.state = "unknown"
	} else {
		pct := float64(current) / float64(limit) * 100
		t := m.Thresholds
		switch {
		case pct >= t.Emergency:
			m.state = "emergency"
		case old == "emergency" && pct >= t.Emergency-t.Hysteresis:
			m.state = "emergency"
		case pct >= t.Critical:
			m.state = "critical"
		case old == "critical" && pct >= t.Critical-t.Hysteresis:
			m.state = "critical"
		case pct >= t.Warning:
			m.state = "warning"
		case old == "warning" && pct >= t.Warning-t.Hysteresis:
			m.state = "warning"
		case old == "warning" || old == "critical" || old == "emergency":
			m.state = "recovered"
		default:
			m.state = "normal"
		}
	}
	s.State = m.state
	s.Events = map[string]uint64{}
	next := map[string]uint64{}
	for _, scope := range []string{"cgroup.memory.events.", "cgroup.memory.events.local."} {
		for _, event := range []string{"low", "high", "max", "oom", "oom_kill", "oom_group_kill"} {
			key := scope + event
			if value, ok := s.Metrics[key]; ok {
				next[key] = value
				if previous, exists := m.previous[key]; exists {
					if value >= previous {
						if value > previous {
							s.Events[key] = value - previous
						}
					} else {
						s.Warnings = append(s.Warnings, "counter_reset:"+key)
					}
				}
			}
		}
	}
	m.previous = next
	return old != m.state
}

func Elevated(state string) bool {
	return state == "warning" || state == "critical" || state == "emergency"
}
