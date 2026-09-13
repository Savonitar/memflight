package collector

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/model"
)

type fixture struct {
	collector *Collector
	procRoot  string
	cgRoot    string
	procDir   string
	cgDir     string
}

func newFixture(t testing.TB) fixture {
	t.Helper()
	root := t.TempDir()
	f := fixture{
		procRoot: filepath.Join(root, "proc"), cgRoot: filepath.Join(root, "cgroup"),
		procDir: filepath.Join(root, "proc", "42"), cgDir: filepath.Join(root, "cgroup", "workload"),
	}
	files := map[string]string{
		filepath.Join(f.procRoot, "self", "mountinfo"): "29 23 0:26 / /sys/fs/cgroup rw,nosuid,nodev,noexec - cgroup2 cgroup rw\n",
		filepath.Join(f.procDir, "stat"):               processStat(42, 12345),
		filepath.Join(f.procDir, "cgroup"):             "0::/workload\n",
		filepath.Join(f.procDir, "status"): "Name:\tPRIVATE_SENTINEL\nUid:\t1234 1234 1234 1234\n" +
			"VmRSS:\t100 kB\nRssAnon:\t60 kB\nRssFile:\t30 kB\nRssShmem:\t10 kB\n" +
			"VmSwap:\t5 kB\nVmSize:\t400 kB\nThreads:\t7\n",
		filepath.Join(f.procDir, "smaps_rollup"): "00000000-ffffffff ---p 00000000 00:00 0 [rollup]\n" +
			"Rss: 100 kB\nPss: 90 kB\nPrivate_Clean: 1 kB\nPrivate_Dirty: 2 kB\n" +
			"Shared_Clean: 3 kB\nShared_Dirty: 4 kB\nAnonymous: 60 kB\nSwap: 5 kB\nUnknown: 999 kB\n",
		filepath.Join(f.cgDir, "memory.current"):      "104857600\n",
		filepath.Join(f.cgDir, "memory.max"):          "134217728\n",
		filepath.Join(f.cgDir, "memory.peak"):         "110000000\n",
		filepath.Join(f.cgDir, "memory.min"):          "0\n",
		filepath.Join(f.cgDir, "memory.low"):          "0\n",
		filepath.Join(f.cgDir, "memory.high"):         "max\n",
		filepath.Join(f.cgDir, "memory.swap.current"): "5120\n",
		filepath.Join(f.cgDir, "memory.swap.peak"):    "10240\n",
		filepath.Join(f.cgDir, "memory.swap.max"):     "max\n",
		filepath.Join(f.cgDir, "memory.events"):       "low 0\nhigh 1\nmax 2\noom 3\noom_kill 4\noom_group_kill 5\nunknown 100\n",
		filepath.Join(f.cgDir, "memory.events.local"): "low 0\nhigh 0\nmax 0\noom 1\noom_kill 1\n",
		filepath.Join(f.cgDir, "memory.pressure"):     "some avg10=1.25 avg60=0.75 avg300=0.25 total=123456\nfull avg10=0.50 avg60=0.20 avg300=0.10 total=1234\n",
	}
	var stat strings.Builder
	for key := range statFields {
		fmt.Fprintf(&stat, "%s 1024\n", key)
	}
	stat.WriteString("PRIVATE_SENTINEL 999\n")
	files[filepath.Join(f.cgDir, "memory.stat")] = stat.String()
	for name, data := range files {
		writeFile(t, name, data)
	}
	for i := 0; i < 3; i++ {
		writeFile(t, filepath.Join(f.procDir, "fd", strconv.Itoa(i)), "")
	}
	// Forbidden process content exists but has no collection path.
	writeFile(t, filepath.Join(f.procDir, "environ"), "PRIVATE_SENTINEL")
	writeFile(t, filepath.Join(f.procDir, "cmdline"), "PRIVATE_SENTINEL")
	var err error
	f.collector, err = New(f.procRoot, f.cgRoot, 42)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func writeFile(t testing.TB, filename, data string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(filename), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filename, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

func processStat(pid int, ticks uint64) string {
	return fmt.Sprintf("%d (PRIVATE_SENTINEL (worker)) S %s %d 0\n", pid, strings.Repeat("0 ", 18), ticks)
}

func take(c *Collector) model.Sample {
	return c.Collect(time.Date(2026, 9, 6, 12, 0, 0, 0, time.FixedZone("example", 3600)), 5*time.Second)
}

func hasWarning(s model.Sample, warning string) bool {
	for _, actual := range s.Warnings {
		if actual == warning {
			return true
		}
	}
	return false
}

func TestCollectAllowlistedMetrics(t *testing.T) {
	f := newFixture(t)
	s := take(f.collector)
	if s.Present == nil || !*s.Present || s.Target.StartTicks != 12345 || s.Target.PID != 42 {
		t.Fatalf("unexpected target: %+v, present=%v", s.Target, s.Present)
	}
	if len(s.Target.CgroupID) != 32 || strings.Contains(s.Target.CgroupID, "workload") {
		t.Fatalf("cgroup ID is not opaque: %q", s.Target.CgroupID)
	}
	if s.Time.Location() != time.UTC || s.ElapsedNS != int64(5*time.Second) {
		t.Fatalf("incorrect timing: %+v", s)
	}
	for key, want := range map[string]uint64{
		"cgroup.memory.current": 104857600, "cgroup.memory.max": 134217728,
		"cgroup.memory.events.oom_kill": 4, "cgroup.memory.events.local.oom_kill": 1,
		"cgroup.memory.stat.anon": 1024, "cgroup.memory.pressure.some.total": 123456,
		"proc.status.RssAnon": 61440, "proc.status.Threads": 7, "proc.smaps.Rss": 102400,
		"proc.smaps.Private_Dirty": 2048, "proc.fd_count": 3,
	} {
		if actual, ok := s.Metrics[key]; !ok || actual != want {
			t.Errorf("%s = %d (present %v), want %d", key, actual, ok, want)
		}
	}
	for key := range statFields {
		if s.Metrics["cgroup.memory.stat."+key] != 1024 {
			t.Errorf("missing memory.stat field %s", key)
		}
	}
	if s.Pressure["cgroup.memory.pressure.some.avg10"] != 1.25 || len(s.Pressure) != 6 {
		t.Errorf("unexpected pressure: %v", s.Pressure)
	}
	if !reflect.DeepEqual(s.Unlimited, []string{"cgroup.memory.high", "cgroup.memory.swap.max"}) {
		t.Errorf("unexpected unlimited fields: %v", s.Unlimited)
	}
	encoded, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"PRIVATE_SENTINEL", f.procRoot, f.cgRoot, "workload", "Uid", "Unknown", "unknown"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("non-allowlisted content %q reached sample", forbidden)
		}
	}
}

func TestMissingOptionalMetricsAndUnlimited(t *testing.T) {
	f := newFixture(t)
	if err := os.Remove(filepath.Join(f.cgDir, "memory.peak")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(f.procDir, "smaps_rollup")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(f.cgDir, "memory.max"), "max\n")
	s := take(f.collector)
	for _, absent := range []string{"cgroup.memory.max", "cgroup.memory.peak", "proc.smaps.Rss"} {
		if _, exists := s.Metrics[absent]; exists {
			t.Errorf("missing/unlimited metric %s became numeric", absent)
		}
	}
	if s.Metrics["proc.status.VmRSS"] != 102400 || s.Present == nil || !*s.Present {
		t.Fatal("optional capability failure prevented core collection")
	}
	if !hasWarning(s, "cgroup_memory_limit_unlimited") || !hasWarning(s, "proc_smaps_rollup_unavailable") {
		t.Errorf("missing capability warnings: %v", s.Warnings)
	}
}

func TestMalformedMetricsDoNotBecomeZero(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.cgDir, "memory.current"), "PRIVATE_SENTINEL\n")
	writeFile(t, filepath.Join(f.cgDir, "memory.stat"), "anon nope\nfile 123\nsock -1\nslab 4 garbage\n")
	writeFile(t, filepath.Join(f.cgDir, "memory.pressure"), "some avg10=NaN avg60=Inf avg300=101 total=-1\nfull avg10=0.2 total=45\n")
	writeFile(t, filepath.Join(f.procDir, "status"), "VmRSS: -1 kB\nVmSize: 18446744073709551615 kB\nRssAnon: 10 MB\nThreads: 5\nRssFile: 1 kB\n")
	s := take(f.collector)
	for _, absent := range []string{"cgroup.memory.current", "cgroup.memory.stat.anon", "cgroup.memory.stat.sock", "cgroup.memory.stat.slab", "proc.status.VmRSS", "proc.status.VmSize", "proc.status.RssAnon", "cgroup.memory.pressure.some.total"} {
		if _, exists := s.Metrics[absent]; exists {
			t.Errorf("invalid metric %s retained", absent)
		}
	}
	if len(s.Pressure) != 1 || s.Pressure["cgroup.memory.pressure.full.avg10"] != 0.2 {
		t.Errorf("invalid pressure accepted: %v", s.Pressure)
	}
	if s.Metrics["cgroup.memory.stat.file"] != 123 || s.Metrics["proc.status.RssFile"] != 1024 || s.Metrics["proc.status.Threads"] != 5 {
		t.Error("malformed neighboring fields suppressed valid metrics")
	}
	if _, err := json.Marshal(s); err != nil {
		t.Fatalf("sample is not JSON safe: %v", err)
	}
}

func TestTargetAbsenceAndReuse(t *testing.T) {
	f := newFixture(t)
	first := take(f.collector)
	writeFile(t, filepath.Join(f.procDir, "stat"), processStat(42, 23456))
	second := take(f.collector)
	if first.Target.StartTicks == second.Target.StartTicks || second.Target.StartTicks != 23456 {
		t.Fatal("PID reuse did not change process identity")
	}
	if err := os.Remove(filepath.Join(f.procDir, "stat")); err != nil {
		t.Fatal(err)
	}
	missing := take(f.collector)
	if missing.Present == nil || *missing.Present || !hasWarning(missing, "target_missing") {
		t.Fatalf("missing process was not distinguished: %+v", missing)
	}
	if _, exists := missing.Metrics["proc.status.VmRSS"]; exists {
		t.Fatal("process metrics survived process disappearance")
	}
	writeFile(t, filepath.Join(f.procDir, "stat"), "invalid PRIVATE_SENTINEL")
	invalid := take(f.collector)
	if invalid.Present != nil || hasWarning(invalid, "target_missing") || len(invalid.Metrics) != 0 {
		t.Fatalf("invalid identity was treated as absence: %+v", invalid)
	}
	var inaccessible model.Sample
	setIdentityFailure(&inaccessible, os.ErrPermission)
	if inaccessible.Present != nil || !hasWarning(inaccessible, "target_identity_permission_denied") {
		t.Fatalf("permission denied treated as process exit: %+v", inaccessible)
	}
}

func TestFinalCgroupCountersOnExit(t *testing.T) {
	for _, state := range []string{"missing", "Z", "X"} {
		t.Run(state, func(t *testing.T) {
			f := newFixture(t)
			first := take(f.collector)
			writeFile(t, filepath.Join(f.cgDir, "memory.events"), "oom 5\noom_kill 6\n")
			if state == "missing" {
				if err := os.Remove(filepath.Join(f.procDir, "stat")); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, filepath.Join(f.procDir, "stat"), strings.Replace(processStat(42, 12345), ") S ", ") "+state+" ", 1))
			}
			last := take(f.collector)
			if last.Present == nil || *last.Present || last.Target != first.Target {
				t.Fatalf("exit identity was not preserved: %+v", last)
			}
			if last.Metrics["cgroup.memory.events.oom_kill"] != 6 {
				t.Fatal("exit-time OOM counter was lost")
			}
			for key := range last.Metrics {
				if strings.HasPrefix(key, "proc.") {
					t.Fatalf("process metric collected after exit: %s", key)
				}
			}
		})
	}
}

func TestFinalCgroupRejectsReplacementsAndUnseenTarget(t *testing.T) {
	t.Run("replacement_cgroup", func(t *testing.T) {
		f := newFixture(t)
		take(f.collector)
		// Keep the old inode alive under a different name so an immediate
		// filesystem inode reuse cannot make this fixture ambiguous.
		if err := os.Rename(f.cgDir, f.cgDir+"-old"); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.cgDir, "memory.events"), "oom_kill 999\n")
		if err := os.Remove(filepath.Join(f.procDir, "stat")); err != nil {
			t.Fatal(err)
		}
		s := take(f.collector)
		if len(s.Metrics) != 0 || !hasWarning(s, "cached_cgroup_identity_unavailable_or_changed") {
			t.Fatalf("replacement cgroup was read: %+v", s)
		}
	})
	t.Run("replacement_zombie", func(t *testing.T) {
		f := newFixture(t)
		take(f.collector)
		writeFile(t, filepath.Join(f.procDir, "stat"), strings.Replace(processStat(42, 99999), ") S ", ") Z ", 1))
		s := take(f.collector)
		if len(s.Metrics) != 0 || s.Target.StartTicks != 99999 {
			t.Fatalf("new zombie inherited previous lifetime: %+v", s)
		}
	})
	t.Run("no_prior_sample", func(t *testing.T) {
		f := newFixture(t)
		if err := os.Remove(filepath.Join(f.procDir, "stat")); err != nil {
			t.Fatal(err)
		}
		s := take(f.collector)
		if len(s.Metrics) != 0 || s.Target.CgroupID != "" {
			t.Fatalf("unobserved process acquired a cgroup: %+v", s)
		}
	})
}

func TestTargetCgroupMapping(t *testing.T) {
	for _, tc := range []struct {
		name, root, membership, expectedWarning string
		collect                                 bool
	}{
		{"hierarchy_root", "/", "/workload", "cgroup_ancestor_limits_not_evaluated", true},
		{"bind_mounted_subtree", "/host/container", "/host/container/workload", "cgroup_ancestor_limits_may_be_hidden", true},
		{"outside_mount", "/host/container", "/other/workload", "target_cgroup_outside_visible_mount", false},
		{"hidden_path", "/", "/../../workload", "target_cgroup_invalid_or_unreadable", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			writeFile(t, filepath.Join(f.procRoot, "self", "mountinfo"), "29 23 0:26 "+tc.root+" /sys/fs/cgroup rw - cgroup2 cgroup rw\n")
			writeFile(t, filepath.Join(f.procDir, "cgroup"), "0::"+tc.membership+"\n")
			s := take(f.collector)
			_, collected := s.Metrics["cgroup.memory.current"]
			if collected != tc.collect || !hasWarning(s, tc.expectedWarning) {
				t.Fatalf("collected %v, warnings %v", collected, s.Warnings)
			}
			if s.Metrics["proc.status.Threads"] != 7 {
				t.Fatal("cgroup mapping failure prevented process metrics")
			}
		})
	}
}

func TestNeverUsesAgentMembership(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.procRoot, "self", "cgroup"), "0::/agent\n")
	writeFile(t, filepath.Join(f.cgRoot, "agent", "memory.current"), "999\n")
	s := take(f.collector)
	if s.Metrics["cgroup.memory.current"] != 104857600 {
		t.Fatal("collector used agent cgroup instead of explicit target")
	}
}

func TestUnverifiedMountMappingOmitsCgroupMetrics(t *testing.T) {
	for _, tc := range []struct {
		name, mountinfo, warning string
	}{
		{"missing", "", "cgroup_mount_mapping_unverified"},
		{"unmatched", "29 23 0:26 / /other/mount rw - cgroup2 cgroup rw\n", "cgroup_mount_mapping_unverified"},
		{"ambiguous", "29 23 0:26 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n30 23 0:26 /workload /sys/fs/cgroup rw - cgroup2 cgroup rw\n", "cgroup_mount_mapping_ambiguous"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			mountinfo := filepath.Join(f.procRoot, "self", "mountinfo")
			if tc.mountinfo == "" {
				if err := os.Remove(mountinfo); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFile(t, mountinfo, tc.mountinfo)
			}
			s := take(f.collector)
			for key := range s.Metrics {
				if strings.HasPrefix(key, "cgroup.") {
					t.Fatalf("unverified mapping produced cgroup metric %s", key)
				}
			}
			if s.Target.CgroupID != "" || len(s.Unlimited) != 0 || len(s.Pressure) != 0 {
				t.Fatalf("unverified mapping retained cgroup observations: %+v", s)
			}
			if s.Metrics["proc.status.Threads"] != 7 || !hasWarning(s, tc.warning) {
				t.Fatalf("unexpected degradation: %+v", s)
			}
		})
	}
}

func TestUnreadableFilesDegradeOnlyAffectedCapability(t *testing.T) {
	for _, tc := range []struct {
		name, source, missingMetric, survivingMetric, warning string
	}{
		{"status", "proc/status", "proc.status.VmRSS", "proc.smaps.Rss", "proc_status_permission_denied"},
		{"smaps", "proc/smaps_rollup", "proc.smaps.Rss", "proc.status.VmRSS", "proc_smaps_rollup_permission_denied"},
		{"current", "cgroup/memory.current", "cgroup.memory.current", "proc.status.VmRSS", "cgroup_memory_current_permission_denied"},
		{"events", "cgroup/memory.events", "cgroup.memory.events.oom_kill", "cgroup.memory.current", "cgroup_memory_events_permission_denied"},
		{"mountinfo", "self/mountinfo", "cgroup.memory.current", "proc.status.VmRSS", "cgroup_mountinfo_permission_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			kind, filename, _ := strings.Cut(tc.source, "/")
			var dir string
			switch kind {
			case "proc":
				dir = f.procDir
			case "cgroup":
				dir = f.cgDir
			case "self":
				dir = filepath.Join(f.procRoot, "self")
			}
			filename = filepath.Join(dir, filename)
			if err := os.Chmod(filename, 0); err != nil {
				t.Skipf("platform cannot create unreadable fixture: %v", err)
			}
			t.Cleanup(func() {
				if err := os.Chmod(filename, 0o600); err != nil {
					t.Errorf("restore fixture permission: %v", err)
				}
			})
			opened, err := os.Open(filename)
			if err == nil {
				opened.Close()
				t.Skip("root or platform bypasses mode-based read permissions")
			}
			if !errors.Is(err, os.ErrPermission) {
				t.Fatalf("unreadable fixture failed for unexpected reason: %v", err)
			}
			s := take(f.collector)
			if _, exists := s.Metrics[tc.missingMetric]; exists {
				t.Fatalf("unreadable source retained %s", tc.missingMetric)
			}
			if _, exists := s.Metrics[tc.survivingMetric]; !exists {
				t.Fatalf("unreadable source suppressed %s", tc.survivingMetric)
			}
			if s.Present == nil || !*s.Present || !hasWarning(s, tc.warning) {
				t.Fatalf("unexpected permission failure state: %+v", s)
			}
		})
	}
}

func TestReadBounds(t *testing.T) {
	f := newFixture(t)
	writeFile(t, filepath.Join(f.procDir, "status"), strings.Repeat("x", maxFileBytes+1))
	s := take(f.collector)
	if _, exists := s.Metrics["proc.status.VmRSS"]; exists || !hasWarning(s, "proc_status_too_large") {
		t.Fatal("oversized kernel file was not bounded")
	}
	if s.Metrics["proc.smaps.Rss"] != 102400 {
		t.Fatal("oversized file suppressed unrelated metrics")
	}
}

func TestFDSymlinkTargetsAreNotResolved(t *testing.T) {
	f := newFixture(t)
	// A dangling descriptor link remains countable; its destination need not
	// exist or be accessible. Windows can prohibit unprivileged symlink creation.
	if err := os.Symlink(filepath.Join(t.TempDir(), "PRIVATE_SENTINEL"), filepath.Join(f.procDir, "fd", "9")); err != nil {
		t.Skip("symlink creation unavailable")
	}
	s := take(f.collector)
	if s.Metrics["proc.fd_count"] != 4 {
		t.Fatal("descriptor links were resolved or excluded")
	}
}

func TestFDEnumerationBoundIncludesNonNumericNames(t *testing.T) {
	var examined int
	_, err := countFDNames(func(n int) ([]string, error) {
		examined += n
		return make([]string, n), nil
	})
	if !errors.Is(err, errTooLarge) || examined > maxFDEntries+128 {
		t.Fatalf("directory enumeration exceeded its bound: entries=%d err=%v", examined, err)
	}
}

func TestHelpersAndValidation(t *testing.T) {
	if _, err := New("", "", 0); err == nil {
		t.Fatal("zero PID accepted")
	}
	c, err := New("", "", 1)
	if err != nil || c.procRoot != filepath.Clean("/proc") || c.cgroupRoot != filepath.Clean("/sys/fs/cgroup") {
		t.Fatalf("wrong default roots: %+v, %v", c, err)
	}
	for _, value := range []string{"relative", "/../secret", "/safe/../../secret", "/a\\..\\secret", "/bad\x00"} {
		if safeHierarchyPath(value) {
			t.Errorf("unsafe hierarchy path accepted: %q", value)
		}
	}
	if got := unescapeMount(`/a\040b\134c`); got != "/a b\\c" {
		t.Errorf("mount escaping: %q", got)
	}
	if warningFor("source", errors.New("PRIVATE_SENTINEL")) != "source_invalid_or_unreadable" {
		t.Fatal("error text leaked into warning")
	}
	s := model.Sample{Metrics: map[string]uint64{}, Pressure: map[string]float64{}}
	parseProcessFields(fmt.Sprintf("Rss: %d kB\n", uint64(math.MaxUint64/1024)), "proc.smaps", smapsFields, &s)
	if s.Metrics["proc.smaps.Rss"] != math.MaxUint64/1024*1024 {
		t.Fatal("largest safe kB conversion was rejected")
	}
}

func BenchmarkCollect(b *testing.B) {
	f := newFixture(b)
	now := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f.collector.Collect(now, time.Duration(i)*time.Second)
	}
}
