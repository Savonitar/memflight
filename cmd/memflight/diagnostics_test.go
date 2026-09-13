package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Savonitar/memflight/internal/incident"
	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/recorder"
)

type failingDiagnostics struct {
	calls     atomic.Int32
	attempted chan struct{}
}

func (w *failingDiagnostics) Write(p []byte) (int, error) {
	if w.calls.Add(1) == 1 {
		close(w.attempted)
	}
	return 0, errors.New("synthetic diagnostics failure")
}

func diagnosticTestConfig() incident.Config {
	return incident.Config{Interval: 10 * time.Millisecond, ElevatedInterval: 10 * time.Millisecond, SyncInterval: time.Second, MaxBytes: 256 * 1024, Retention: 2, Thresholds: recorder.DefaultThresholds()}
}

func assertRecordingCompleted(t *testing.T, root string) {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		found = true
		b, err := incident.Read(filepath.Join(root, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !b.Manifest.Closed || b.Manifest.Termination != "target-disappeared" || len(b.Samples) != 4 {
			t.Fatal("diagnostics failure interrupted recording", b.Manifest, len(b.Samples))
		}
	}
	if !found {
		t.Fatal("no incident recorded")
	}
}

func TestFailedDiagnosticsDoNotStopRecording(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	diagnostics := &failingDiagnostics{attempted: make(chan struct{})}
	if err := record(context.Background(), &diagnosticGatedSampler{attempted: diagnostics.attempted}, root, diagnosticTestConfig(), diagnostics); err != nil {
		t.Fatal(err)
	}
	if calls := diagnostics.calls.Load(); calls != 1 {
		t.Fatalf("expected one failed attempt without retries, got %d", calls)
	}
	assertRecordingCompleted(t, root)
}

// Ensure the failure-path test actually exercises a diagnostic write before the
// recording ends and cancels pending best-effort messages.
type diagnosticGatedSampler struct {
	base      fakeSampler
	attempted <-chan struct{}
}

func (s *diagnosticGatedSampler) Collect(now time.Time, elapsed time.Duration) model.Sample {
	if s.base.n == 1 {
		select {
		case <-s.attempted:
		case <-time.After(2 * time.Second):
		}
	}
	return s.base.Collect(now, elapsed)
}

type blockedDiagnostics struct {
	entered  chan struct{}
	release  chan struct{}
	returned chan struct{}
	once     sync.Once
}

func (w *blockedDiagnostics) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	close(w.returned)
	return len(p), nil
}

type continuingSampler struct {
	base     fakeSampler
	observed chan int
}

func (s *continuingSampler) Collect(now time.Time, elapsed time.Duration) model.Sample {
	sample := s.base.Collect(now, elapsed)
	present := true
	sample.Present = &present
	select {
	case s.observed <- s.base.n:
	default:
	}
	return sample
}

func TestBlockedDiagnosticsDoNotDelayCollectionOrShutdown(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("writer requires flock")
	}
	root := t.TempDir()
	sink := &blockedDiagnostics{entered: make(chan struct{}), release: make(chan struct{}), returned: make(chan struct{})}
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(sink.release) }) }
	ctx, cancel := context.WithCancel(context.Background())
	samples := &continuingSampler{observed: make(chan int, 16)}
	done := make(chan error, 1)
	go func() {
		defer close(done)
		done <- record(ctx, samples, root, diagnosticTestConfig(), sink)
	}()
	t.Cleanup(func() {
		cancel()
		release()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("recording did not stop during cleanup")
		}
	})
	select {
	case <-sink.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("diagnostic worker never reached sink")
	}
	deadline := time.After(2 * time.Second)
	for {
		select {
		case count := <-samples.observed:
			if count >= 4 {
				goto collected
			}
		case <-deadline:
			t.Fatal("blocked diagnostics stopped sampling")
		}
	}
collected:
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown waited for the blocked diagnostic sink")
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		found = true
		bundle, err := incident.Read(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if !bundle.Manifest.Closed || bundle.Manifest.Termination != "clean" || len(bundle.Samples) < 4 {
			t.Fatal("recording did not finalize independently of blocked diagnostics", bundle.Manifest, len(bundle.Samples))
		}
	}
	if !found {
		t.Fatal("no incident was recorded")
	}
	// The I/O operation itself remains blocked until its owner releases it;
	// clean it up so this test leaves no diagnostic worker behind.
	release()
	select {
	case <-sink.returned:
	case <-time.After(2 * time.Second):
		t.Fatal("released diagnostic write did not return")
	}
}

// A real fd 2 pipe is necessary: Go's SIGPIPE handling cannot be reproduced with
// a synthetic io.Writer. The subprocess receives only these test arguments and
// an empty environment; no target command lines or environments are inspected.
func TestBrokenStderrProcess(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires Unix pipes and flock")
	}
	if len(os.Args) >= 3 && os.Args[len(os.Args)-2] == "memflight-diagnostics-helper" {
		root := os.Args[len(os.Args)-1]
		if err := record(context.Background(), &fakeSampler{}, root, diagnosticTestConfig(), os.Stderr); err != nil {
			t.Fatal(err)
		}
		// Async diagnostics are allowed to be dropped at shutdown. Force a real
		// fd 2 write as well so this regression always exercises Go's policy.
		if _, err := os.Stderr.Write([]byte("memflight broken stderr regression\n")); !errors.Is(err, syscall.EPIPE) {
			t.Fatalf("expected EPIPE from closed stderr: %v", err)
		}
		return
	}
	root := t.TempDir()
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := readEnd.Close(); err != nil {
		t.Fatal(err)
	}
	defer writeEnd.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestBrokenStderrProcess$", "--", "memflight-diagnostics-helper", root)
	cmd.Env = []string{}
	cmd.Stderr = writeEnd
	if err := cmd.Run(); err != nil {
		t.Fatal("recorder terminated on broken stderr", err)
	}
	assertRecordingCompleted(t, root)
}
