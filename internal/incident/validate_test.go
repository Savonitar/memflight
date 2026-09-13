package incident

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/schema"
)

func validationManifest() Manifest {
	first := sample(0)
	return Manifest{SchemaVersion: SchemaVersion, AgentVersion: "test", StartedAt: first.Time,
		Termination: "unknown", Target: target(first.Target), CgroupVersion: 2,
		Config: config(), Capabilities: []string{"cgroup.memory.current"}}
}

func writeValidationBundle(t *testing.T, m Manifest, samples ...sampleRecord) string {
	t.Helper()
	dir := t.TempDir()
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	var lines []byte
	for _, sample := range samples {
		line, err := json.Marshal(sample)
		if err != nil {
			t.Fatal(err)
		}
		lines = append(lines, line...)
		lines = append(lines, '\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "samples.jsonl"), lines, 0600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func requireInvalidBundle(t *testing.T, dir string) {
	t.Helper()
	b, err := Read(dir)
	if err == nil {
		t.Fatal("invalid incident accepted")
	}
	if b.Manifest.SchemaVersion != 0 || len(b.Samples) != 0 || len(b.Warnings) != 0 {
		t.Fatal("rejected input exposed a partial bundle")
	}
}

func TestManifestSemanticValidation(t *testing.T) {
	bad := []struct {
		name   string
		change func(*Manifest)
	}{
		{"config", func(m *Manifest) { m.Config.Interval = 0 }},
		{"thresholds", func(m *Manifest) { m.Config.Thresholds.Warning = 101 }},
		{"schema", func(m *Manifest) { m.SchemaVersion++ }},
		{"missing_start", func(m *Manifest) { m.StartedAt = time.Time{} }},
		{"non_utc", func(m *Manifest) { m.StartedAt = m.StartedAt.In(time.FixedZone("offset", 3600)) }},
		{"pid", func(m *Manifest) { m.Target.PID = 0 }},
		{"cgroup_version", func(m *Manifest) { m.CgroupVersion = 1 }},
		{"cgroup_identity", func(m *Manifest) { m.Target.CgroupID = "" }},
		{"cgroup_path", func(m *Manifest) { m.Target.CgroupID = "/host/path" }},
		{"version_size", func(m *Manifest) { m.AgentVersion = strings.Repeat("v", maxIdentityBytes+1) }},
		{"open_clean", func(m *Manifest) { m.Termination = "clean" }},
		{"open_end", func(m *Manifest) { m.EndedAt = &m.StartedAt }},
		{"closed_without_end", func(m *Manifest) { m.Closed = true }},
		{"abrupt_without_recovery", func(m *Manifest) { m.Closed = true; m.Termination = "abrupt" }},
		{"abrupt_with_end", func(m *Manifest) {
			m.Closed = true
			m.Termination = "abrupt"
			m.EndedAt = &m.StartedAt
			m.RecoveredAt = &m.StartedAt
		}},
		{"unknown_termination", func(m *Manifest) { m.Closed = true; m.EndedAt = &m.StartedAt; m.Termination = "oom" }},
		{"unknown_capability", func(m *Manifest) { m.Capabilities = []string{"arbitrary"} }},
		{"duplicate_capability", func(m *Manifest) { m.Capabilities = append(m.Capabilities, m.Capabilities[0]) }},
		{"long_warning", func(m *Manifest) { m.Warnings = []string{strings.Repeat("w", maxStringBytes+1)} }},
		{"warning_count", func(m *Manifest) { m.Warnings = make([]string, maxWarnings+1) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			m := validationManifest()
			tc.change(&m)
			requireInvalidBundle(t, writeValidationBundle(t, m, record(sample(0))))
		})
	}
	for _, termination := range []string{"clean", "unknown", "target-disappeared", "abrupt"} {
		t.Run("accepted_"+termination, func(t *testing.T) {
			m := validationManifest()
			m.Closed = true
			m.Termination = termination
			// Wall time can move backward even between initialization and finish.
			backward := m.StartedAt.Add(-time.Hour)
			if termination == "abrupt" {
				m.RecoveredAt = &backward
			} else {
				m.EndedAt = &backward
			}
			if _, err := Read(writeValidationBundle(t, m, record(sample(0)))); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSampleSemanticValidation(t *testing.T) {
	bad := []struct {
		name   string
		change func(*sampleRecord)
	}{
		{"state", func(s *sampleRecord) { s.State = "oom" }},
		{"time", func(s *sampleRecord) { s.Time = time.Time{} }},
		{"negative_elapsed", func(s *sampleRecord) { s.ElapsedNS = -1 }},
		{"pid_conflict", func(s *sampleRecord) { s.Target.PID++ }},
		{"start_conflict", func(s *sampleRecord) { s.Target.StartTicks++ }},
		{"cgroup_conflict", func(s *sampleRecord) { s.Target.CgroupID = "other" }},
		{"unknown_metric", func(s *sampleRecord) { s.Metrics["arbitrary"] = 1 }},
		{"unknown_pressure", func(s *sampleRecord) { s.Pressure = map[string]float64{"arbitrary": 1} }},
		{"negative_pressure", func(s *sampleRecord) { s.Pressure = map[string]float64{"cgroup.memory.pressure.some.avg10": -1} }},
		{"excess_pressure", func(s *sampleRecord) { s.Pressure = map[string]float64{"cgroup.memory.pressure.some.avg10": 100.001} }},
		{"unknown_event", func(s *sampleRecord) { s.Events = map[string]uint64{"arbitrary": 1} }},
		{"event_without_counter", func(s *sampleRecord) { s.Events = map[string]uint64{"cgroup.memory.events.oom_kill": 1} }},
		{"event_exceeds_counter", func(s *sampleRecord) {
			s.Metrics["cgroup.memory.events.oom_kill"] = 1
			s.Events = map[string]uint64{"cgroup.memory.events.oom_kill": 2}
		}},
		{"unknown_unlimited", func(s *sampleRecord) { s.Unlimited = []string{"cgroup.memory.current"} }},
		{"conflicting_unlimited", func(s *sampleRecord) {
			s.Metrics["cgroup.memory.max"] = 256
			s.Unlimited = []string{"cgroup.memory.max"}
		}},
		{"duplicate_unlimited", func(s *sampleRecord) { s.Unlimited = []string{"cgroup.memory.max", "cgroup.memory.max"} }},
		{"long_warning", func(s *sampleRecord) { s.Warnings = []string{strings.Repeat("w", maxStringBytes+1)} }},
		{"warning_count", func(s *sampleRecord) { s.Warnings = make([]string, maxWarnings+1) }},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			s := record(sample(1))
			tc.change(&s)
			requireInvalidBundle(t, writeValidationBundle(t, validationManifest(), record(sample(0)), s))
		})
	}
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		s := record(sample(0))
		s.Pressure = map[string]float64{"cgroup.memory.pressure.some.avg10": v}
		if s.validate(validationManifest(), 0, false) == nil {
			t.Fatal("non-finite pressure accepted")
		}
	}
}

func TestUnavailableIdentityAndAllKnownObservations(t *testing.T) {
	m := validationManifest()
	first := record(sample(0))
	missing := record(sample(1))
	missing.Target = Target{PID: 42}
	missing.Present = nil
	missing.Metrics = nil
	missing.State = "unknown"
	last := record(sample(2))
	absent := false
	last.Present = &absent
	last.State = "emergency"
	last.Time = first.Time.Add(-time.Hour)
	last.Metrics = map[string]uint64{}
	for _, key := range schema.MetricKeys() {
		last.Metrics[key] = 10
	}
	// Independent reads may produce current > max; this is not corruption.
	last.Metrics["cgroup.memory.current"] = 11
	for _, key := range []string{"cgroup.memory.high", "cgroup.memory.swap.max"} {
		delete(last.Metrics, key)
	}
	last.Unlimited = []string{"cgroup.memory.high", "cgroup.memory.swap.max"}
	last.Pressure = map[string]float64{"cgroup.memory.pressure.some.avg10": 0, "cgroup.memory.pressure.full.avg300": 100}
	last.Events = map[string]uint64{"cgroup.memory.events.oom_kill": 1}
	last.Warnings = []string{"unknown warning is retained but not trusted", "counter_reset:cgroup.memory.events.high"}
	if _, err := Read(writeValidationBundle(t, m, first, missing, last)); err != nil {
		t.Fatal(err)
	}
}

func TestWriterClosedUnknownAndTemporaryIdentityLoss(t *testing.T) {
	s := openStore(t, t.TempDir())
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	missing := sample(1)
	missing.Target = model.Identity{PID: 42}
	missing.Present = nil
	missing.Metrics = nil
	missing.State = "unknown"
	for _, v := range []model.Sample{sample(0), missing, sample(2)} {
		if err := w.Append(v, false); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Finish("unknown", sample(0).Time.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(w.Path); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeRejectsDuplicateNullUnknownAndOversizedShapes(t *testing.T) {
	base, err := json.Marshal(record(sample(0)))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"duplicate_pid":      strings.Replace(string(base), `"pid":42`, `"pid":42,"pid":99`, 1),
		"case_duplicate_pid": strings.Replace(string(base), `"pid":42`, `"pid":42,"PID":99`, 1),
		"duplicate_metric":   strings.Replace(string(base), `"cgroup.memory.current":0`, `"cgroup.memory.current":0,"cgroup.memory.current":1`, 1),
		"numeric_null":       strings.Replace(string(base), `"cgroup.memory.current":0`, `"cgroup.memory.current":null`, 1),
		"unknown_top_field":  strings.TrimSuffix(string(base), "}") + `,"arbitrary":1}`,
		"trailing_object":    string(base) + `{}`,
		"too_many_fields":    `{"metrics":{` + strings.Repeat(`"x":1,`, 65) + `"last":1}}`,
		"too_deep":           strings.Repeat(`{"nested":`, 10) + `0` + strings.Repeat(`}`, 10),
	} {
		t.Run(name, func(t *testing.T) {
			dir := writeValidationBundle(t, validationManifest())
			if err := os.WriteFile(filepath.Join(dir, "samples.jsonl"), []byte(data+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			requireInvalidBundle(t, dir)
		})
	}
	m := validationManifest()
	data, _ := json.Marshal(m)
	dir := writeValidationBundle(t, m)
	data = []byte(strings.Replace(string(data), `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1))
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	requireInvalidBundle(t, dir)
}

func TestDecodeRejectsUnicodeAliasesAtEveryObjectLevel(t *testing.T) {
	base, err := json.Marshal(record(sample(0)))
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"unicode_metrics_null":         strings.Replace(strings.Replace(string(base), `"metrics":`, `"metricſ":`, 1), `"cgroup.memory.current":0`, `"cgroup.memory.current":null`, 1),
		"escaped_unicode_metrics_null": strings.Replace(strings.Replace(string(base), `"metrics":`, `"metric\u017f":`, 1), `"cgroup.memory.current":0`, `"cgroup.memory.current":null`, 1),
		"unicode_duplicate_state":      strings.Replace(string(base), `"state":"normal"`, `"state":"invalid","ſtate":"normal"`, 1),
		"unicode_target_field":         strings.Replace(string(base), `"start_ticks":100`, `"ſtart_ticks":100`, 1),
		"unicode_map_key":              strings.Replace(string(base), `"cgroup.memory.current":0`, `"cgroup.memory.ſtat.anon":0`, 1),
		"ascii_case_alias":             strings.Replace(string(base), `"metrics":`, `"Metrics":`, 1),
		"nested_number_null":           strings.Replace(string(base), `"start_ticks":100`, `"start_ticks":null`, 1),
		"elapsed_number_null":          strings.Replace(string(base), `"elapsed_ns":0`, `"elapsed_ns":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var decoded sampleRecord
			if decodeBounded([]byte(data), &decoded) == nil {
				t.Fatal("noncanonical field or null number accepted")
			}
			dir := writeValidationBundle(t, validationManifest())
			if err := os.WriteFile(filepath.Join(dir, "samples.jsonl"), []byte(data+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			requireInvalidBundle(t, dir)
		})
	}
	manifest, err := json.Marshal(validationManifest())
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{
		"unicode_duplicate_schema": strings.Replace(string(manifest), `"schema_version":1`, `"schema_version":99,"ſchema_version":1`, 1),
		"unicode_config_field":     strings.Replace(string(manifest), `"sync_interval_ns":`, `"ſync_interval_ns":`, 1),
		"unicode_threshold_field":  strings.Replace(string(manifest), `"hysteresis_points":`, `"hyſteresis_points":`, 1),
		"ascii_config_case_alias":  strings.Replace(string(manifest), `"config":`, `"Config":`, 1),
		"closed_boolean_null":      strings.Replace(string(manifest), `"closed":false`, `"closed":null`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			var decoded Manifest
			if decodeBounded([]byte(data), &decoded) == nil {
				t.Fatal("noncanonical manifest field or null boolean accepted")
			}
			dir := writeValidationBundle(t, validationManifest())
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			requireInvalidBundle(t, dir)
		})
	}
}

func TestDecodeAcceptsEscapedCanonicalNamesAndNullableScopes(t *testing.T) {
	base, err := json.Marshal(record(sample(0)))
	if err != nil {
		t.Fatal(err)
	}
	data := strings.Replace(string(base), `"metrics":`, `"metri\u0063s":`, 1)
	var decoded sampleRecord
	if err := decodeBounded([]byte(data), &decoded); err != nil {
		t.Fatal("canonical escaped field rejected", err)
	}
	data = strings.Replace(string(base), `"metrics":{"cgroup.memory.current":0}`, `"metrics":null`, 1)
	data = strings.Replace(data, `"present":true`, `"present":null`, 1)
	decoded = sampleRecord{}
	if err := decodeBounded([]byte(data), &decoded); err != nil || decoded.Metrics != nil || decoded.Present != nil {
		t.Fatal("nullable metric/presence scope rejected", err)
	}
}
