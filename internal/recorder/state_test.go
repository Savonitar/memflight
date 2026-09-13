package recorder

import (
	"math"
	"testing"

	"github.com/Savonitar/memflight/internal/model"
)

func TestTransitionsAndHysteresis(t *testing.T) {
	m := Machine{Thresholds: DefaultThresholds()}
	for _, test := range []struct {
		usage uint64
		want  string
	}{{60, "normal"}, {96, "emergency"}, {92, "emergency"}, {89, "warning"}, {79, "warning"}, {74, "recovered"}, {74, "normal"}, {91, "critical"}, {86, "critical"}, {84, "warning"}} {
		s := model.Sample{Target: model.Identity{PID: 1, StartTicks: 2, CgroupID: "a"}, Metrics: map[string]uint64{"cgroup.memory.current": test.usage, "cgroup.memory.max": 100}}
		m.Observe(&s)
		if s.State != test.want {
			t.Fatalf("usage %d: got %s, want %s", test.usage, s.State, test.want)
		}
	}
}

func TestUnknownAndCounters(t *testing.T) {
	m := Machine{Thresholds: DefaultThresholds()}
	s := model.Sample{Target: model.Identity{PID: 1, StartTicks: 2, CgroupID: "a"}, Metrics: map[string]uint64{"cgroup.memory.events.oom_kill": 5}}
	m.Observe(&s)
	if s.State != "unknown" || len(s.Events) != 0 {
		t.Fatal(s)
	}
	s.Metrics["cgroup.memory.events.oom_kill"] = 7
	m.Observe(&s)
	if s.Events["cgroup.memory.events.oom_kill"] != 2 {
		t.Fatal(s.Events)
	}
	s.Metrics["cgroup.memory.events.oom_kill"] = 1
	m.Observe(&s)
	if len(s.Events) != 0 || len(s.Warnings) != 1 {
		t.Fatal(s)
	}
	s.Target.StartTicks++
	s.Metrics["cgroup.memory.events.oom_kill"] = 10
	m.Observe(&s)
	if len(s.Events) != 0 {
		t.Fatal("PID reuse mixed counters")
	}
	delete(s.Metrics, "cgroup.memory.events.oom_kill")
	m.Observe(&s)
	s.Metrics["cgroup.memory.events.oom_kill"] = 20
	m.Observe(&s)
	if len(s.Events) != 0 {
		t.Fatal("missing counter must break baseline")
	}
}

func TestInvalidThresholds(t *testing.T) {
	for _, v := range []Thresholds{{90, 80, 95, 5}, {80, 90, 95, 0}, {80, 90, 101, 5}, {math.NaN(), 90, 95, 5}} {
		if v.Validate() == nil {
			t.Fatal(v)
		}
	}
}
