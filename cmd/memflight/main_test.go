package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/incident"
	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/recorder"
)

type fakeSampler struct {
	n              int
	reuse          bool
	discoverCgroup bool
	warnings       []string
}

func (f *fakeSampler) Collect(now time.Time, elapsed time.Duration) model.Sample {
	f.n++
	present := f.n < 4
	start := uint64(10)
	if f.reuse && f.n >= 2 {
		start = 20
	}
	cgroup := "cg"
	if f.discoverCgroup && f.n == 1 {
		cgroup = ""
	}
	return model.Sample{Time: now, ElapsedNS: int64(elapsed), Target: model.Identity{PID: 42, StartTicks: start, CgroupID: cgroup}, Present: &present, Metrics: map[string]uint64{"cgroup.memory.current": uint64(f.n) * 20, "cgroup.memory.max": 100, "cgroup.memory.events.oom_kill": uint64(f.n / 4)}, Warnings: f.warnings}
}

func TestRecordingToOfflineReport(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	var log bytes.Buffer
	config := incident.Config{Interval: 10 * time.Millisecond, ElevatedInterval: 10 * time.Millisecond, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
	if err := record(context.Background(), &fakeSampler{}, root, config, &log); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	var path string
	for _, e := range entries {
		if e.IsDir() {
			path = filepath.Join(root, e.Name())
		}
	}
	b, err := incident.Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(b.Samples) != 4 || b.Manifest.Termination != "target-disappeared" {
		t.Fatal(b.Manifest, len(b.Samples))
	}
	if len(b.Warnings) != 0 || b.Samples[0].ElapsedNS != 0 {
		t.Fatal("fresh recording falsely marked truncated", b.Warnings)
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"report", "--json", path}, &output, &log); err != nil {
		t.Fatal(err)
	}
	var r map[string]any
	if json.Unmarshal(output.Bytes(), &r) != nil {
		t.Fatal(output.String())
	}
	if !strings.Contains(output.String(), "observed_oom_counter_increase") || !strings.Contains(output.String(), "exit_cause_unresolved") {
		t.Fatal(output.String())
	}
}

func TestPIDReuseStartsNewIncident(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	var log bytes.Buffer
	config := incident.Config{Interval: 10 * time.Millisecond, ElevatedInterval: 10 * time.Millisecond, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
	if err := record(context.Background(), &fakeSampler{reuse: true}, root, config, &log); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	var ids []uint64
	for _, e := range entries {
		if e.IsDir() {
			b, err := incident.Read(filepath.Join(root, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			ids = append(ids, b.Manifest.Target.StartTicks)
			for _, s := range b.Samples {
				if s.Target.StartTicks != b.Manifest.Target.StartTicks {
					t.Fatal("mixed lifetimes")
				}
			}
		}
	}
	if len(ids) != 2 || ids[0] != 10 || ids[1] != 20 {
		t.Fatal(ids)
	}
}

func TestInvalidCLI(t *testing.T) {
	for _, args := range [][]string{{"nonsense"}, {"agent"}, {"report"}, {"report", "--bad"}} {
		var b bytes.Buffer
		if run(context.Background(), args, &b, &b) == nil {
			t.Fatal(args)
		}
	}
}

func TestNewlyAvailableCgroupStartsIdentifiedManifest(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	var log bytes.Buffer
	config := incident.Config{Interval: 10 * time.Millisecond, ElevatedInterval: 10 * time.Millisecond, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
	if err := record(context.Background(), &fakeSampler{discoverCgroup: true}, root, config, &log); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	var manifests []incident.Manifest
	for _, e := range entries {
		if e.IsDir() {
			b, err := incident.Read(filepath.Join(root, e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			manifests = append(manifests, b.Manifest)
			if b.Samples[0].ElapsedNS != 0 {
				t.Fatal("new incident retained previous elapsed origin")
			}
		}
	}
	if len(manifests) != 2 || manifests[0].CgroupVersion != 0 || manifests[1].CgroupVersion != 2 || manifests[1].Target.CgroupID != "cg" {
		t.Fatal(manifests)
	}
}

func TestCancellationFinalizesCleanly(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := t.TempDir()
	var log bytes.Buffer
	config := incident.Config{Interval: time.Second, ElevatedInterval: time.Second, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
	if err := record(ctx, &fakeSampler{}, root, config, &log); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(root)
	for _, e := range entries {
		if e.IsDir() {
			b, err := incident.Read(filepath.Join(root, e.Name()))
			if err != nil || !b.Manifest.Closed || b.Manifest.Termination != "clean" {
				t.Fatal(b.Manifest, err)
			}
		}
	}
}

func TestReportIncludesSafeCollectionAndManifestWarnings(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	var diagnostics bytes.Buffer
	source := &fakeSampler{warnings: []string{"cgroup_ancestor_limits_may_be_hidden", "proc_smaps_rollup_permission_denied", "PRIVATE_INJECTED_REVIEW2"}}
	if err := record(context.Background(), source, root, diagnosticTestConfig(), &diagnostics); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var path string
	for _, e := range entries {
		if e.IsDir() {
			path = filepath.Join(root, e.Name())
		}
	}
	var output bytes.Buffer
	if err := report([]string{"--json", path}, &output); err != nil {
		t.Fatal(err)
	}
	var result struct {
		CollectionWarnings []struct {
			Code string `json:"code"`
		} `json:"collection_warnings"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	codes := map[string]bool{}
	for _, warning := range result.CollectionWarnings {
		codes[warning.Code] = true
	}
	for _, expected := range []string{"cgroup_ancestor_limits_may_be_hidden", "proc_smaps_rollup_permission_denied", "buffered_disk_writes_may_be_lost_on_machine_failure"} {
		if !codes[expected] {
			t.Fatalf("report dropped warning %s", expected)
		}
	}
	if strings.Contains(output.String(), "PRIVATE_INJECTED_REVIEW2") {
		t.Fatal("unknown source text leaked into report")
	}
	output.Reset()
	if err := report([]string{path}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "cgroup_ancestor_limits_may_be_hidden") || strings.Contains(output.String(), "PRIVATE_INJECTED_REVIEW2") {
		t.Fatal("terminal report did not preserve warning privacy/visibility")
	}
}
