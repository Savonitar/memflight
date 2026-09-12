package analyzer

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/model"
)

func observations(count int) []model.Sample {
	samples := make([]model.Sample, count)
	for i := range samples {
		samples[i] = model.Sample{
			Time:      time.Date(2026, 1, 1, 0, 0, i*5, 0, time.UTC),
			ElapsedNS: int64(i) * int64(5*time.Second),
			Target:    model.Identity{PID: 10, StartTicks: 500, CgroupID: "opaque-test-group"},
			Metrics: map[string]uint64{
				"cgroup.memory.current":               64 * mib,
				"cgroup.memory.max":                   256 * mib,
				"cgroup.memory.stat.anon":             32 * mib,
				"cgroup.memory.stat.file":             16 * mib,
				"cgroup.memory.swap.current":          0,
				"cgroup.memory.events.oom_kill":       0,
				"cgroup.memory.events.local.oom_kill": 0,
				"proc.status.RssAnon":                 30 * mib,
				"proc.status.Threads":                 4,
				"proc.fd_count":                       10,
			},
		}
	}
	return samples
}

func setValues(samples []model.Sample, key string, values ...uint64) {
	for i, v := range values {
		samples[i].Metrics[key] = v
	}
}

func finding(report Report, code string) *Finding {
	for i := range report.Findings {
		if report.Findings[i].Code == code {
			return &report.Findings[i]
		}
	}
	return nil
}

func TestObservedPatterns(t *testing.T) {
	tests := []struct {
		name, key, code string
		values          []uint64
	}{
		{"anonymous", "cgroup.memory.stat.anon", "gradual_anonymous_growth", []uint64{32 * mib, 40 * mib, 48 * mib, 56 * mib}},
		{"jump", "cgroup.memory.current", "sampled_memory_jump", []uint64{64 * mib, 65 * mib, 110 * mib, 110 * mib}},
		{"file", "cgroup.memory.stat.file", "file_memory_growth", []uint64{16 * mib, 20 * mib, 25 * mib, 30 * mib}},
		{"swap", "cgroup.memory.swap.current", "swap_usage_growth", []uint64{0, mib, 3 * mib, 8 * mib}},
		{"threads", "proc.status.Threads", "thread_count_growth", []uint64{4, 5, 6, 9}},
		{"descriptors", "proc.fd_count", "file_descriptor_growth", []uint64{10, 20, 30, 40}},
		{"recovery", "cgroup.memory.current", "observed_memory_recovery", []uint64{64 * mib, 100 * mib, 70 * mib, 64 * mib}},
		{"physical limit", "cgroup.memory.current", "high_cgroup_memory_usage", []uint64{240 * mib, 240 * mib, 240 * mib, 240 * mib}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			samples := observations(len(tc.values))
			setValues(samples, tc.key, tc.values...)
			got := finding(Analyze(samples, "clean"), tc.code)
			if got == nil || len(got.Evidence) == 0 || got.Confidence == "" {
				t.Fatalf("missing supported finding %s: %+v", tc.code, got)
			}
		})
	}
}

func TestGrowthUsesElapsedTimeAndIgnoresWallClock(t *testing.T) {
	samples := observations(4)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 40*mib, 48*mib, 56*mib)
	samples[3].Time = samples[0].Time.Add(-time.Hour)
	got := finding(Analyze(samples, "clean"), "gradual_anonymous_growth")
	if got == nil || !strings.Contains(got.Evidence[0], "15.000 seconds") {
		t.Fatalf("wall clock affected duration: %+v", got)
	}
}

func TestDoesNotJoinIdentitiesOrElapsedResets(t *testing.T) {
	for _, change := range []string{"pid", "start", "cgroup", "elapsed", "negative_elapsed"} {
		t.Run(change, func(t *testing.T) {
			samples := observations(4)
			setValues(samples, "cgroup.memory.stat.anon", 32*mib, 40*mib, 48*mib, 56*mib)
			for i := 2; i < len(samples); i++ {
				switch change {
				case "pid":
					samples[i].Target.PID++
				case "start":
					samples[i].Target.StartTicks++
				case "cgroup":
					samples[i].Target.CgroupID = "another-group"
				case "elapsed":
					samples[i].ElapsedNS -= int64(10 * time.Second)
				case "negative_elapsed":
					samples[i].ElapsedNS = -1
				}
			}
			if got := finding(Analyze(samples, "clean"), "gradual_anonymous_growth"); got != nil {
				t.Fatalf("joined boundary: %+v", got)
			}
		})
	}
}

func TestMissingMetricsAreNotZeroOrBridged(t *testing.T) {
	samples := observations(4)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 40*mib, 48*mib, 56*mib)
	delete(samples[1].Metrics, "cgroup.memory.stat.anon")
	delete(samples[0].Metrics, "cgroup.memory.swap.current")
	setValues(samples[1:], "cgroup.memory.swap.current", 8*mib, 8*mib, 8*mib)
	report := Analyze(samples, "clean")
	if finding(report, "gradual_anonymous_growth") != nil || finding(report, "swap_usage_growth") != nil {
		t.Fatalf("inferred across missing metrics: %+v", report)
	}
}

func TestPartialCgroupDataCanUseProcessEvidence(t *testing.T) {
	samples := observations(4)
	setValues(samples, "proc.status.RssAnon", 30*mib, 38*mib, 46*mib, 54*mib)
	for i := range samples {
		samples[i].Target.CgroupID = ""
	}
	got := finding(Analyze(samples, "clean"), "gradual_anonymous_growth")
	if got == nil || !strings.Contains(got.Evidence[0], "proc.status.RssAnon") {
		t.Fatalf("missing process-only analysis: %+v", got)
	}
}

func TestUnidentifiedOrAbsentProcessSuppressesProcessTrends(t *testing.T) {
	for _, invalid := range []string{"pid", "start", "absent"} {
		t.Run(invalid, func(t *testing.T) {
			samples := observations(4)
			setValues(samples, "proc.fd_count", 10, 20, 30, 40)
			for i := range samples {
				switch invalid {
				case "pid":
					samples[i].Target.PID = 0
				case "start":
					samples[i].Target.StartTicks = 0
				case "absent":
					present := false
					samples[i].Present = &present
				}
			}
			if got := finding(Analyze(samples, "clean"), "file_descriptor_growth"); got != nil {
				t.Fatalf("used untrustworthy identity: %+v", got)
			}
		})
	}
}

func TestDisappearancePreservesPriorProcessTrendsAndFinalCgroupOOM(t *testing.T) {
	samples := observations(5)
	setValues(samples, "proc.fd_count", 10, 20, 30, 40, 0)
	absent := false
	samples[4].Present = &absent
	for key := range samples[4].Metrics {
		if strings.HasPrefix(key, "proc.") {
			delete(samples[4].Metrics, key)
		}
	}
	samples[4].Metrics["cgroup.memory.events.local.oom_kill"] = 1
	report := Analyze(samples, "target-disappeared")
	got := finding(report, "file_descriptor_growth")
	if got == nil || !strings.Contains(got.Evidence[0], "over 15.000 seconds") {
		t.Fatalf("lost process prefix or included absent duration: %+v", got)
	}
	if finding(report, "observed_oom_counter_increase") == nil {
		t.Fatal("lost terminal cgroup OOM counter")
	}
	if !strings.Contains(strings.Join(report.Limitations, " "), "before the first observation marking the target absent") {
		t.Fatal("process coverage limitation is missing")
	}
}

func TestOOMExitPreservesGrowthAndDoesNotBecomeRecovery(t *testing.T) {
	samples := observations(5)
	setValues(samples, "cgroup.memory.current", 64*mib, 128*mib, 192*mib, 240*mib, 16*mib)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 64*mib, 96*mib, 128*mib, 4*mib)
	setValues(samples, "proc.status.RssAnon", 30*mib, 62*mib, 94*mib, 126*mib, 0)
	setValues(samples, "cgroup.memory.stat.file", 16*mib, 20*mib, 25*mib, 30*mib, mib)
	setValues(samples, "cgroup.memory.swap.current", 0, 4*mib, 8*mib, 12*mib, 0)
	absent := false
	samples[4].Present = &absent
	for key := range samples[4].Metrics {
		if strings.HasPrefix(key, "proc.") {
			delete(samples[4].Metrics, key)
		}
	}
	samples[4].Metrics["cgroup.memory.events.local.oom_kill"] = 1
	report := Analyze(samples, "target-disappeared")
	for _, code := range []string{"gradual_anonymous_growth", "file_memory_growth", "swap_usage_growth"} {
		got := finding(report, code)
		if got == nil || !strings.Contains(got.Evidence[0], "over 15.000 seconds") {
			t.Fatalf("lost pre-exit growth or used exit duration for %s: %+v", code, got)
		}
	}
	for _, code := range []string{"high_cgroup_memory_usage", "observed_oom_counter_increase", "exit_cause_unresolved"} {
		if finding(report, code) == nil {
			t.Fatalf("lost pressure or terminal evidence: %s", code)
		}
	}
	if got := finding(report, "observed_memory_recovery"); got != nil {
		t.Fatalf("target exit became workload recovery: %+v", got)
	}
}

func TestRecoveryBeforeExitIsStillObserved(t *testing.T) {
	samples := observations(5)
	setValues(samples, "cgroup.memory.current", 64*mib, 100*mib, 70*mib, 64*mib, 8*mib)
	absent := false
	samples[4].Present = &absent
	got := finding(Analyze(samples, "target-disappeared"), "observed_memory_recovery")
	if got == nil || !strings.Contains(got.Evidence[0], "to 67108864 bytes") || !strings.Contains(got.Evidence[0], "over 10.000 seconds") {
		t.Fatalf("recovery before exit was lost or joined with exit: %+v", got)
	}
}

func TestExitOnlyWindowRetainsPressureWithoutWorkloadJump(t *testing.T) {
	samples := observations(2)
	setValues(samples, "cgroup.memory.current", 64*mib, 240*mib)
	absent := false
	samples[1].Present = &absent
	report := Analyze(samples, "target-disappeared")
	if finding(report, "sampled_memory_jump") != nil || finding(report, "high_cgroup_memory_usage") == nil {
		t.Fatalf("exit was classified as workload jump, or cgroup pressure was lost: %+v", report)
	}
}

func TestSpikeNeedsShortAdjacentWindow(t *testing.T) {
	samples := observations(2)
	setValues(samples, "cgroup.memory.current", 64*mib, 110*mib)
	samples[1].ElapsedNS = int64(time.Hour)
	if got := finding(Analyze(samples, "clean"), "sampled_memory_jump"); got != nil {
		t.Fatalf("a recording gap became a spike: %+v", got)
	}
}

func TestSparseAnonymousSamplesCannotEstablishGradualGrowth(t *testing.T) {
	samples := observations(4)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 40*mib, 48*mib, 56*mib)
	for i := range samples {
		samples[i].ElapsedNS = int64(i) * int64(time.Hour)
	}
	if got := finding(Analyze(samples, "clean"), "gradual_anonymous_growth"); got != nil {
		t.Fatalf("sparse snapshots became gradual growth: %+v", got)
	}
}

func TestNoGrowthFromSmallNoiseOrSingleAnonymousJump(t *testing.T) {
	samples := observations(4)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 32*mib, 56*mib, 56*mib)
	setValues(samples, "proc.status.Threads", 4, 5, 4, 5)
	report := Analyze(samples, "clean")
	if finding(report, "gradual_anonymous_growth") != nil || finding(report, "thread_count_growth") != nil {
		t.Fatalf("overclassified noise or jump: %+v", report)
	}
}

func TestOOMCountersAreNotAddedTogetherOrAttributedToTarget(t *testing.T) {
	samples := observations(4)
	setValues(samples, "cgroup.memory.events.local.oom_kill", 7, 7, 9, 9)
	setValues(samples, "cgroup.memory.events.oom_kill", 10, 10, 12, 12)
	report := Analyze(samples, "target-disappeared")
	got := finding(report, "observed_oom_counter_increase")
	if got == nil || !strings.Contains(got.Evidence[0], "local.oom_kill increased by 2") || !strings.Contains(got.Evidence[1], "not proof that the target was killed") {
		t.Fatalf("wrong OOM evidence: %+v", got)
	}
	if finding(report, "exit_cause_unresolved") == nil {
		t.Fatal("cgroup OOM wrongly resolved target exit cause")
	}
	count := 0
	for _, item := range report.Findings {
		if item.Code == "observed_oom_counter_increase" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("overlapping counters generated %d findings", count)
	}
}

func TestOOMResetBaselineMissingAndIdentityAreNotEvidence(t *testing.T) {
	for _, mode := range []string{"reset", "baseline", "missing", "identity"} {
		t.Run(mode, func(t *testing.T) {
			samples := observations(2)
			switch mode {
			case "reset":
				setValues(samples, "cgroup.memory.events.oom_kill", 9, 0)
			case "baseline":
				setValues(samples, "cgroup.memory.events.oom_kill", 9, 9)
			case "missing":
				delete(samples[0].Metrics, "cgroup.memory.events.oom_kill")
				samples[1].Metrics["cgroup.memory.events.oom_kill"] = 9
			case "identity":
				setValues(samples, "cgroup.memory.events.oom_kill", 0, 9)
				samples[1].Target.StartTicks++
			}
			if got := finding(Analyze(samples, "abrupt"), "observed_oom_counter_increase"); got != nil {
				t.Fatalf("false OOM evidence: %+v", got)
			}
		})
	}
}

func TestHierarchicalOOMScopeIsExplicit(t *testing.T) {
	samples := observations(2)
	setValues(samples, "cgroup.memory.events.oom_kill", 0, 1)
	report := Analyze(samples, "clean")
	if finding(report, "observed_oom_counter_increase") == nil || !strings.Contains(strings.Join(report.Limitations, " "), "descendant") {
		t.Fatalf("missing hierarchical scope: %+v", report)
	}
}

func TestPhysicalLimitDoesNotAddSwapOrAssumeUnlimitedIsZero(t *testing.T) {
	samples := observations(2)
	setValues(samples, "cgroup.memory.current", 240*mib, 240*mib)
	setValues(samples, "cgroup.memory.swap.current", 200*mib, 200*mib)
	if got := finding(Analyze(samples, "clean"), "high_cgroup_memory_usage"); got == nil || !strings.Contains(got.Evidence[0], "93.8%") {
		t.Fatalf("incorrect physical ratio: %+v", got)
	}
	for i := range samples {
		delete(samples[i].Metrics, "cgroup.memory.max")
		samples[i].Unlimited = []string{"cgroup.memory.max"}
	}
	if finding(Analyze(samples, "clean"), "high_cgroup_memory_usage") != nil {
		t.Fatal("unlimited cgroup treated as zero-byte limit")
	}
}

func TestInputTextIsNeverEchoed(t *testing.T) {
	samples := observations(2)
	samples[0].Warnings = []string{"secret-application-content"}
	samples[0].Target.CgroupID = "secret-application-content"
	samples[0].State = "secret-application-content"
	samples[0].Metrics["secret-application-content"] = 42
	report := Analyze(samples, "secret-application-content")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret-application-content") {
		t.Fatal("input text leaked into report")
	}
}

func TestContradictoryLimitIsNotUsed(t *testing.T) {
	samples := observations(2)
	setValues(samples, "cgroup.memory.current", 240*mib, 240*mib)
	for i := range samples {
		samples[i].Unlimited = []string{"cgroup.memory.max"}
	}
	report := Analyze(samples, "clean")
	if finding(report, "high_cgroup_memory_usage") != nil || !strings.Contains(strings.Join(report.Limitations, " "), "contradictory") {
		t.Fatalf("contradictory limit was used or not explained: %+v", report)
	}
}

func TestEmptyReportGolden(t *testing.T) {
	compareReportGolden(t, "empty", Analyze(nil, "clean"))
}

type failedWriter struct{}

func (failedWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

func TestFormatTextPropagatesErrors(t *testing.T) {
	if err := FormatText(failedWriter{}, Analyze(nil, "clean")); err == nil {
		t.Fatal("writer error was dropped")
	}
}
