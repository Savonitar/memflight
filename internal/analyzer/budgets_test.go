package analyzer

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/Savonitar/memflight/internal/model"
)

var updateGoldens = flag.Bool("update-analyzer-goldens", false, "update analyzer JSON and text golden fixtures")

func compareReportGolden(t *testing.T, name string, report Report) {
	t.Helper()
	for extension, format := range map[string]func(io.Writer, Report) error{"json": FormatJSON, "txt": FormatText} {
		var actual bytes.Buffer
		if err := format(&actual, report); err != nil {
			t.Fatal(err)
		}
		path := "testdata/" + name + "." + extension
		if *updateGoldens {
			if err := os.WriteFile(path, actual.Bytes(), 0600); err != nil {
				t.Fatal(err)
			}
		}
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual.Bytes(), expected) {
			t.Fatalf("golden %s mismatch\nactual:\n%s\nexpected:\n%s", path, actual.Bytes(), expected)
		}
	}
}

func TestOOMGrowthAndWarningsGolden(t *testing.T) {
	samples := observations(5)
	setValues(samples, "cgroup.memory.current", 64*mib, 128*mib, 192*mib, 240*mib, 16*mib)
	setValues(samples, "cgroup.memory.stat.anon", 32*mib, 64*mib, 96*mib, 128*mib, 4*mib)
	setValues(samples, "proc.status.RssAnon", 30*mib, 62*mib, 94*mib, 126*mib, 0)
	for i := range samples {
		samples[i].Warnings = []string{"proc_smaps_rollup_permission_denied", "cgroup_ancestor_limits_not_evaluated"}
	}
	absent := false
	samples[4].Present = &absent
	for key := range samples[4].Metrics {
		if strings.HasPrefix(key, "proc.") {
			delete(samples[4].Metrics, key)
		}
	}
	samples[4].Metrics["cgroup.memory.events.local.oom_kill"] = 1
	samples[4].Warnings = append(samples[4].Warnings, "target_exited_state")
	report := Analyze(samples, "target-disappeared", []string{"sampling_can_miss_short_spikes", "cgroup_oom_does_not_identify_target_victim"}, []string{"partial_final_line_ignored"})
	compareReportGolden(t, "oom-growth-warnings", report)
}

func TestWarningAggregationRecognizesExactSafeCodes(t *testing.T) {
	samples := observations(3)
	for i := range samples {
		samples[i].Warnings = []string{"proc_smaps_rollup_permission_denied", "proc_smaps_rollup_permission_denied"}
	}
	samples[0].Warnings = append(samples[0].Warnings,
		"cgroup_ancestor_limits_may_be_hidden", "cgroup_ancestor_limits_not_evaluated", "cgroup_memory_limit_unlimited",
		"cgroup_mount_mapping_unverified", "cgroup_mount_mapping_ambiguous", "target_cgroup_outside_visible_mount",
		"counter_reset:cgroup.memory.events.local.oom_kill", "cgroup_memory_current_invalid", "proc_status_too_large")
	samples[1].Warnings = append(samples[1].Warnings,
		"proc_private_secret_permission_denied", "counter_reset:cgroup.memory.events.private_secret", "cgroup_memory_current_invalid_private_secret",
		"cgroup_mount_mapping_unverified\nprivate_secret", strings.Repeat("private_secret", 10000))
	report := Analyze(samples, "clean", []string{"proc_smaps_rollup_permission_denied", "previous_execution_not_finalized"}, []string{"recording_not_finalized"})
	var text bytes.Buffer
	if err := FormatJSON(&text, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text.String(), "private_secret") {
		t.Fatal("unrecognized warning text was echoed")
	}
	keys := make([]string, 0, len(report.CollectionWarnings))
	for _, warning := range report.CollectionWarnings {
		keys = append(keys, warning.Code)
		if warning.Code == "proc_smaps_rollup_permission_denied" && (warning.SampleCount != 3 || !warning.Metadata) {
			t.Fatalf("wrong warning count: %+v", warning)
		}
	}
	if !sort.StringsAreSorted(keys) || len(keys) != 12 {
		t.Fatalf("missing, duplicated, or unstable warning codes: %v", keys)
	}
	if !strings.Contains(strings.Join(report.Limitations, " "), "Unrecognized collection warning codes were omitted") {
		t.Fatal("omission was not explained")
	}
}

func TestAllRegisteredWarningMessagesFitBudgets(t *testing.T) {
	for code, message := range warningMessages {
		if len(code) > 128 || len(message) > 512 || message == "" {
			t.Fatalf("invalid registered warning: %s", code)
		}
	}
}

func TestSampleAndWindowBudgetsHaveExplicitCoverage(t *testing.T) {
	samples := observations(MaxSamples + 100)
	for i := range samples {
		samples[i].Target.StartTicks += uint64(i)
	}
	report := Analyze(samples, "clean")
	if !report.Truncated || report.SampleCount != len(samples) || report.AnalyzedSampleCount != MaxWindows || report.AnalysisWindows != MaxWindows {
		t.Fatalf("incorrect bounded coverage: %+v", report)
	}
	if !strings.Contains(report.Findings[0].Evidence[0], "Analyzed 32 of 4196") {
		t.Fatal("partial analysis implied complete coverage")
	}
	if len(report.Limitations) > MaxLimitations {
		t.Fatal("unbounded limitations")
	}
	for _, format := range []func(io.Writer, Report) error{FormatText, FormatJSON} {
		var output bytes.Buffer
		if err := format(&output, report); err != nil {
			t.Fatal(err)
		}
		if output.Len() > MaxOutputBytes {
			t.Fatal("unbounded report")
		}
	}
}

func TestFindingBudgetStopsAtWholeWindowBoundary(t *testing.T) {
	var samples []model.Sample
	for window := 0; window < MaxWindows; window++ {
		part := observations(4)
		for i := range part {
			part[i].Target.StartTicks += uint64(window)
		}
		setValues(part, "cgroup.memory.current", 64*mib, 240*mib, 200*mib, 64*mib)
		setValues(part, "cgroup.memory.stat.anon", 32*mib, 48*mib, 64*mib, 80*mib)
		setValues(part, "cgroup.memory.stat.file", 16*mib, 24*mib, 32*mib, 48*mib)
		setValues(part, "cgroup.memory.swap.current", 0, 4*mib, 8*mib, 12*mib)
		setValues(part, "proc.status.Threads", 4, 8, 12, 20)
		setValues(part, "proc.fd_count", 10, 26, 42, 58)
		setValues(part, "cgroup.memory.events.local.oom_kill", 0, 0, 0, 1)
		samples = append(samples, part...)
	}
	allWarnings := make([]string, 0, len(warningMessages))
	for code := range warningMessages {
		allWarnings = append(allWarnings, code)
	}
	sort.Strings(allWarnings)
	report := Analyze(samples, "abrupt", allWarnings)
	if !report.Truncated || report.AnalyzedSampleCount%4 != 0 || len(report.Findings) > MaxFindings || len(report.Findings) < 120 {
		t.Fatalf("finding budget did not retain bounded full windows: count=%d samples=%d", len(report.Findings), report.AnalyzedSampleCount)
	}
	for _, f := range report.Findings {
		if len(f.Evidence) > MaxEvidence {
			t.Fatal("too much evidence")
		}
	}
	for _, format := range []func(io.Writer, Report) error{FormatText, FormatJSON} {
		var output bytes.Buffer
		if err := format(&output, report); err != nil {
			t.Fatal(err)
		}
		if output.Len() > MaxOutputBytes {
			t.Fatal("generated report exceeds output budget")
		}
	}
}

func TestWarningInputBudgetsAreExplicit(t *testing.T) {
	samples := observations(1)
	samples[0].Warnings = make([]string, MaxWarnings+1000)
	for i := range samples[0].Warnings {
		samples[0].Warnings[i] = "target_missing"
	}
	report := Analyze(samples, "clean")
	if !report.Truncated || len(report.CollectionWarnings) != 1 || report.CollectionWarnings[0].SampleCount != 1 {
		t.Fatalf("warning budget or deduplication failed: %+v", report)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestBothFormatsRejectShortWrites(t *testing.T) {
	for _, format := range []func(io.Writer, Report) error{FormatText, FormatJSON} {
		if err := format(shortWriter{}, Analyze(nil, "clean")); !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("short write lost: %v", err)
		}
		if err := format(failedWriter{}, Analyze(nil, "clean")); err == nil {
			t.Fatal("writer failure lost")
		}
	}
}

func TestOversizedExternalReportsWriteNothing(t *testing.T) {
	tooManyEvidence := Report{Findings: []Finding{{Evidence: make([]string, MaxEvidence+1)}}}
	tooLargeField := Report{Findings: []Finding{{Pattern: strings.Repeat("x", 257)}}}
	tooManyFindings := Report{Findings: make([]Finding, MaxFindings+1)}
	tooMuchText := Report{Findings: make([]Finding, MaxFindings)}
	for i := range tooMuchText.Findings {
		tooMuchText.Findings[i].Evidence = make([]string, MaxEvidence)
		for j := range tooMuchText.Findings[i].Evidence {
			tooMuchText.Findings[i].Evidence[j] = strings.Repeat("x", 512)
		}
	}
	for i, report := range []Report{tooManyEvidence, tooLargeField, tooManyFindings, tooMuchText} {
		for _, format := range []func(io.Writer, Report) error{FormatText, FormatJSON} {
			var output bytes.Buffer
			if err := format(&output, report); !errors.Is(err, ErrReportTooLarge) || output.Len() != 0 {
				t.Fatalf("case %d emitted partial or accepted oversized report: %v bytes=%d", i, err, output.Len())
			}
		}
	}
}

func TestOutputBudgetIncludesFormattingAndJSONEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, field string
		format      func(io.Writer, Report) error
	}{
		{"json escapes", strings.Repeat("\x00", 512), FormatJSON},
		{"text decorations", strings.Repeat("x", 250), FormatText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Report{Findings: make([]Finding, MaxFindings)}
			for i := range r.Findings {
				r.Findings[i] = Finding{Code: "pattern", Pattern: "pattern", Confidence: "high", Evidence: make([]string, MaxEvidence)}
				for j := range r.Findings[i].Evidence {
					r.Findings[i].Evidence[j] = tc.field
				}
			}
			if tc.name == "json escapes" {
				r.Findings = r.Findings[:50]
			}
			if err := validateReport(r); err != nil {
				t.Fatalf("fixture should pass structural preflight: %v", err)
			}
			var output bytes.Buffer
			if err := tc.format(&output, r); !errors.Is(err, ErrReportTooLarge) || output.Len() != 0 {
				t.Fatalf("budget overflow wrote data: %v, bytes=%d", err, output.Len())
			}
		})
	}
}

func BenchmarkBoundedWorstCaseAnalysis(b *testing.B) {
	samples := observations(MaxSamples)
	for i := range samples {
		samples[i].Target.CgroupID = fmt.Sprintf("identity-%d", i)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Analyze(samples, "unknown")
	}
}
