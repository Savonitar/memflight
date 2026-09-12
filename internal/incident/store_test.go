package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/recorder"
)

type shortMetadataWriter struct{}

func (shortMetadataWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

func TestMetadataRejectsShortWrite(t *testing.T) {
	if err := writeMetadata(shortMetadataWriter{}, []byte("metadata")); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("expected short-write error, got %v", err)
	}
	var complete bytes.Buffer
	if err := writeMetadata(&complete, []byte("metadata")); err != nil || complete.String() != "metadata" {
		t.Fatal("complete metadata write failed", err)
	}
}

func config() Config {
	return Config{Interval: time.Second, ElevatedInterval: time.Second, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
}
func sample(i int) model.Sample {
	p := true
	return model.Sample{Time: time.Date(2026, 9, 6, 0, 0, i, 0, time.UTC), ElapsedNS: int64(i) * int64(time.Second), Target: model.Identity{PID: 42, StartTicks: 100, CgroupID: "opaque"}, Present: &p, Metrics: map[string]uint64{"cgroup.memory.current": uint64(i)}, State: "normal"}
}
func openStore(t *testing.T, root string) *Store {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires local flock")
	}
	s, err := Open(root, config())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestRotationRetentionAndBound(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	for run := 0; run < 4; run++ {
		w, err := s.Start("test", sample(run))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 1000; i++ {
			v := sample(i)
			if err := w.Append(v, false); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Finish("clean", time.Now()); err != nil {
			t.Fatal(err)
		}
		b, err := Read(w.Path)
		if err != nil {
			t.Fatal(err)
		}
		if len(b.Samples) == 0 || len(b.Samples) >= 1000 || b.Samples[len(b.Samples)-1].ElapsedNS != 999*int64(time.Second) {
			t.Fatal("rotation lost tail or did not bound history")
		}
		if !b.Manifest.Closed || b.Manifest.Termination != "clean" {
			t.Fatal(b.Manifest)
		}
		var bytes int64
		filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() {
				fi, e := d.Info()
				if e != nil {
					return e
				}
				bytes += fi.Size()
			}
			return nil
		})
		if bytes > config().MaxBytes {
			t.Fatalf("storage %d > bound", bytes)
		}
	}
	names, err := s.directories()
	if err != nil || len(names) != 2 {
		t.Fatal(names, err)
	}
}

func TestAbruptRecoveryAndPartialLine(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sample(0), true); err != nil {
		t.Fatal(err)
	}
	path := w.Path
	s.Close()
	f, err := os.OpenFile(filepath.Join(path, "samples.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"time":`)
	f.Close()
	s = openStore(t, root)
	b, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Termination != "abrupt" || !b.Manifest.Closed || b.Manifest.EndedAt != nil || b.Manifest.RecoveredAt == nil {
		t.Fatal(b.Manifest)
	}
	if len(b.Samples) != 1 || !strings.Contains(strings.Join(b.Warnings, ","), "partial_final_line_ignored") {
		t.Fatal(b.Warnings)
	}
}

func TestLockAndForeignContent(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	if other, err := Open(root, config()); err == nil {
		other.Close()
		t.Fatal("concurrent writer accepted")
	}
	s.Close()
	if err := os.WriteFile(filepath.Join(root, "keep.txt"), []byte("unrelated"), 0600); err != nil {
		t.Fatal(err)
	}
	if other, err := Open(root, config()); err == nil {
		other.Close()
		t.Fatal("foreign data accepted")
	}
	if _, err := os.Stat(filepath.Join(root, "keep.txt")); err != nil {
		t.Fatal("foreign file modified")
	}
}

func TestUnsupportedSchemaAndMalformedLine(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	w.Append(sample(0), true)
	w.Finish("clean", time.Now())
	if err := os.WriteFile(filepath.Join(w.Path, "samples.jsonl"), []byte("{bad}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(w.Path); err == nil {
		t.Fatal("malformed complete record accepted")
	}
	m := w.manifest
	m.SchemaVersion = 99
	data, _ := json.Marshal(m)
	os.WriteFile(filepath.Join(w.Path, "manifest.json"), data, 0600)
	if _, err := Read(w.Path); err == nil {
		t.Fatal("future schema accepted")
	}
}

func TestSymlinkIsNotFollowed(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	w.Finish("clean", time.Now())
	s.Close()
	outside := filepath.Join(t.TempDir(), "sentinel")
	os.WriteFile(outside, []byte("preserve"), 0600)
	os.Remove(filepath.Join(w.Path, "summary.json"))
	if err := os.Symlink(outside, filepath.Join(w.Path, "summary.json")); err != nil {
		t.Skip(err)
	}
	if other, err := Open(root, config()); err == nil {
		other.Close()
		t.Fatal("symlink accepted for recovery")
	}
	data, _ := os.ReadFile(outside)
	if string(data) != "preserve" {
		t.Fatal("symlink target modified")
	}
}

func TestHardlinkedScratchDoesNotTruncateOtherFile(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	outside := filepath.Join(t.TempDir(), "sentinel")
	if err := os.WriteFile(outside, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(outside, filepath.Join(w.Path, "metadata.tmp")); err != nil {
		t.Skip(err)
	}
	s = openStore(t, root)
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "preserve" {
		t.Fatal("scratch link target changed", err)
	}
}

func TestInvalidStartPreservesRetainedIncident(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	for i := 0; i < 2; i++ {
		w, err := s.Start("test", sample(i))
		if err != nil {
			t.Fatal(err)
		}
		if err := w.Finish("clean", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := s.directories()
	if _, err := s.Start(strings.Repeat("v", metadataLimit), sample(3)); err == nil {
		t.Fatal("oversized version accepted")
	}
	after, _ := s.directories()
	if strings.Join(before, ",") != strings.Join(after, ",") {
		t.Fatal("invalid start removed prior evidence")
	}
	// These fit the encoded metadata budget but violate schema invariants.
	for _, version := range []string{"", strings.Repeat("v", maxIdentityBytes+1)} {
		if _, err := s.Start(version, sample(3)); err == nil {
			t.Fatal("semantically invalid version accepted")
		}
		after, err := s.directories()
		if err != nil || strings.Join(before, ",") != strings.Join(after, ",") {
			t.Fatal("invalid manifest preflight changed retained evidence", err)
		}
	}
}

func TestRecoveryPreservesWarningCountAndDeduplicates(t *testing.T) {
	for _, count := range []int{1, maxWarnings - 1, maxWarnings} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			root := t.TempDir()
			s := openStore(t, root)
			w, err := s.Start("test", sample(0))
			if err != nil {
				t.Fatal(err)
			}
			m := w.manifest
			m.Warnings = make([]string, count)
			for i := range m.Warnings {
				m.Warnings[i] = "bounded_warning_" + strconv.Itoa(i)
			}
			if count == 1 {
				m.Warnings[0] = "previous_execution_not_finalized"
			}
			if err := atomicJSON(w.Path, "manifest.json", m); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			recovered := openStore(t, root)
			b, err := Read(w.Path)
			if err != nil || b.Manifest.Validate() != nil || b.Manifest.Termination != "abrupt" || b.Manifest.RecoveredAt == nil {
				t.Fatal("recovery produced unreadable metadata", err)
			}
			want := count
			if count == maxWarnings-1 {
				want++
			}
			if len(b.Manifest.Warnings) != want {
				t.Fatalf("warning count %d, want %d", len(b.Manifest.Warnings), want)
			}
			if err := recovered.Close(); err != nil {
				t.Fatal(err)
			}
			// Reopening the already recovered incident must stay valid and stable.
			again := openStore(t, root)
			b, err = Read(w.Path)
			if err != nil || len(b.Manifest.Warnings) != want {
				t.Fatal("second startup cannot read recovered metadata", err)
			}
			if err := again.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestInterruptedRotationAndInitialization(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sample(0), true); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err := os.Rename(filepath.Join(w.Path, "samples.jsonl"), filepath.Join(w.Path, "samples.previous.jsonl")); err != nil {
		t.Fatal(err)
	}
	incomplete := filepath.Join(root, "incident-20260906T000000.000000000Z-aaaaaaaaaaaa")
	os.Mkdir(incomplete, 0700)
	os.WriteFile(filepath.Join(incomplete, "metadata.tmp"), []byte("partial"), 0600)
	s = openStore(t, root)
	b, err := Read(w.Path)
	if err != nil || len(b.Samples) != 1 || b.Manifest.Termination != "abrupt" {
		t.Fatal(b, err)
	}
	if _, err := os.Stat(incomplete); !os.IsNotExist(err) {
		t.Fatal("interrupted initialization not cleaned")
	}
}

func TestNonemptyLockRejected(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, ".writer.lock"), []byte("foreign"), 0600)
	if s, err := Open(root, config()); err == nil {
		s.Close()
		t.Fatal("nonempty lock escaped budget")
	}
}

func TestWriteFailureLeavesUnfinishedManifest(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /dev/full")
	}
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.file.Close(); err != nil {
		t.Fatal(err)
	}
	w.file, err = os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sample(0), false); err == nil {
		t.Fatal("write failure not propagated")
	}
	s.Close()
	b, err := Read(w.Path)
	if err != nil {
		t.Fatal(err)
	}
	if b.Manifest.Closed || b.Manifest.Termination != "unknown" {
		t.Fatal("failed recording marked clean")
	}
}

func TestReadingActiveRecording(t *testing.T) {
	root := t.TempDir()
	s := openStore(t, root)
	w, err := s.Start("test", sample(0))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(sample(0), true); err != nil {
		t.Fatal(err)
	}
	b, err := Read(w.Path)
	if err != nil || len(b.Samples) != 1 {
		t.Fatal(b, err)
	}
	if !strings.Contains(strings.Join(b.Warnings, ","), "recording_not_finalized") {
		t.Fatal("active recording was not distinguished")
	}
}

func TestWriterAlwaysRetainsReportableSampleCount(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	for _, bytes := range []int64{5 * 1024 * 1024, 64 * 1024 * 1024} {
		cfg := config()
		cfg.MaxBytes = bytes
		cfg.Retention = 1
		s, err := Open(t.TempDir(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		w, err := s.Start("test", sample(0))
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i <= MaxReadSamples; i++ {
			if err := w.Append(sample(i), false); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Finish("clean", time.Now()); err != nil {
			t.Fatal(err)
		}
		b, err := Read(w.Path)
		if err != nil {
			t.Fatal("writer produced an unreadable incident", err)
		}
		if len(b.Samples) > MaxReadSamples || b.Samples[len(b.Samples)-1].ElapsedNS != int64(MaxReadSamples)*int64(time.Second) {
			t.Fatal("sample rotation lost recent evidence or exceeded report limit")
		}
		if 2*w.segmentLimit+metadataReserve > MaxReadBytes {
			t.Fatal("writer can exceed reader byte bound")
		}
	}
}

func BenchmarkSampleEncoding(b *testing.B) {
	s := sample(0)
	for _, key := range []string{"cgroup.memory.max", "cgroup.memory.peak", "cgroup.memory.swap.current", "cgroup.memory.stat.anon", "cgroup.memory.stat.file", "cgroup.memory.events.oom_kill", "proc.status.RssAnon", "proc.status.Threads", "proc.fd_count"} {
		s.Metrics[key] = 128 * 1024 * 1024
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := json.Marshal(record(s)); err != nil {
			b.Fatal(err)
		}
	}
}
