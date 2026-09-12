// Memflight records bounded Linux memory evidence and explains it offline.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/Savonitar/memflight/internal/analyzer"
	"github.com/Savonitar/memflight/internal/collector"
	"github.com/Savonitar/memflight/internal/incident"
	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/recorder"
)

var version = "0.1.0-dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		json.NewEncoder(os.Stderr).Encode(map[string]string{"event": "error", "message": err.Error()})
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	if len(args) == 0 {
		usage(out)
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		usage(out)
		return nil
	case "version", "--version":
		fmt.Fprintln(out, "memflight", version)
		return nil
	case "agent":
		return agent(ctx, args[1:], diagnostics)
	case "report":
		return report(args[1:], out)
	default:
		return errors.New("unknown command; use memflight --help")
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Memflight — bounded memory incident recording and offline analysis\n\nUsage:\n  memflight agent --pid PID --output DIRECTORY [options]   (Linux)\n  memflight report [--json] INCIDENT_DIRECTORY\n  memflight version\n\nUse memflight agent --help for sampling and retention options.")
}

func report(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("report", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	jsonOutput := flags.Bool("json", false, "emit stable JSON")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Fprintln(out, "Usage: memflight report [--json] INCIDENT_DIRECTORY")
			return nil
		}
		return errors.New("invalid report options")
	}
	if flags.NArg() != 1 {
		return errors.New("report requires one incident directory; place --json before the directory")
	}
	b, err := incident.Read(flags.Arg(0))
	if err != nil {
		return err
	}
	r := analyzer.Analyze(b.Samples, b.Manifest.Termination, b.Manifest.Warnings, b.Warnings)
	if *jsonOutput {
		return analyzer.FormatJSON(out, r)
	}
	return analyzer.FormatText(out, r)
}

func agent(ctx context.Context, args []string, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	pid := flags.Int("pid", 0, "explicit target process ID (required)")
	output := flags.String("output", "memflight-data", "dedicated persistent recording directory")
	procRoot := flags.String("proc-root", "/proc", "procfs mount root (fixture override)")
	cgroupRoot := flags.String("cgroup-root", "/sys/fs/cgroup", "cgroup v2 mount root (fixture override)")
	interval := flags.Duration("interval", 5*time.Second, "normal sample interval")
	elevated := flags.Duration("elevated-interval", time.Second, "sample interval during elevated usage")
	syncInterval := flags.Duration("sync-interval", 30*time.Second, "sync at the first sample after this interval")
	maxBytes := flags.Int64("max-bytes", 5*1024*1024, "total byte limit across retained incidents")
	retention := flags.Int("retention", 3, "incident count including the active recording")
	duration := flags.Duration("duration", 0, "stop cleanly after this duration; 0 runs until signaled")
	warning := flags.Float64("warning", 80, "warning usage percent of finite memory.max")
	critical := flags.Float64("critical", 90, "critical usage percent")
	emergency := flags.Float64("emergency", 95, "emergency usage percent")
	hysteresis := flags.Float64("hysteresis", 5, "percentage points before lowering severity")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return errors.New("invalid agent options")
	}
	if flags.NArg() != 0 || *pid <= 0 || *duration < 0 || *output == "" {
		return errors.New("agent requires a positive --pid, a dedicated --output and no positional arguments")
	}
	if runtime.GOOS != "linux" {
		return errors.New("agent requires Linux; use memflight report for offline analysis on this platform")
	}
	config := incident.Config{Interval: *interval, ElevatedInterval: *elevated, SyncInterval: *syncInterval, MaxBytes: *maxBytes, Retention: *retention, Thresholds: recorder.Thresholds{Warning: *warning, Critical: *critical, Emergency: *emergency, Hysteresis: *hysteresis}}
	if err := config.Validate(); err != nil {
		return err
	}
	c, err := collector.New(*procRoot, *cgroupRoot, *pid)
	if err != nil {
		return err
	}
	if *duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, *duration)
		defer cancel()
	}
	return record(ctx, c, *output, config, diagnostics)
}

type sampler interface {
	Collect(time.Time, time.Duration) model.Sample
}

type recordingDiagnostic struct {
	Event    string   `json:"event"`
	Incident string   `json:"incident"`
	PID      int      `json:"pid"`
	Warnings []string `json:"warnings,omitempty"`
}

// writeDiagnostics is the only diagnostic worker for a recording session. The
// caller uses a one-item queue and drops new events when it is full. Cancellation
// never waits for this worker: an arbitrary io.Writer cannot be interrupted, so
// a blocked Write can retain this single worker until the sink or process exits.
func writeDiagnostics(ctx context.Context, queue <-chan recordingDiagnostic, sink io.Writer) {
	encoder := json.NewEncoder(sink)
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-queue:
			if ctx.Err() != nil {
				return
			}
			_ = encoder.Encode(event)
		}
	}
}

func record(ctx context.Context, c sampler, output string, config incident.Config, diagnostics io.Writer) error {
	// Go otherwise terminates on EPIPE from stdout/stderr before Write returns.
	// This policy applies only to the agent; report keeps normal pipe behavior.
	signal.Ignore(syscall.SIGPIPE)
	store, err := incident.Open(output, config)
	if err != nil {
		return err
	}
	defer store.Close()
	diagnosticContext, stopDiagnostics := context.WithCancel(ctx)
	defer stopDiagnostics()
	diagnosticQueue := make(chan recordingDiagnostic, 1)
	go writeDiagnostics(diagnosticContext, diagnosticQueue, diagnostics)
	start := time.Now()
	var writer *incident.Writer
	var identity model.Identity
	state := recorder.Machine{Thresholds: config.Thresholds}
	lastSync := start
	for {
		now := time.Now()
		sample := c.Collect(now, now.Sub(start))
		if writer == nil && sample.Present != nil && !*sample.Present {
			return errors.New("configured target is absent")
		}
		changed := writer != nil && sample.Target.StartTicks > 0 && identity.StartTicks > 0 && (sample.Target.StartTicks != identity.StartTicks || sample.Target.PID != identity.PID || (sample.Target.CgroupID != "" && identity.CgroupID != "" && sample.Target.CgroupID != identity.CgroupID))
		// A newly available identity also starts a fresh manifest rather than
		// leaving an identifiable process under an unknown manifest identity.
		changed = changed || (writer != nil && identity.StartTicks == 0 && sample.Target.StartTicks > 0)
		changed = changed || (writer != nil && identity.CgroupID == "" && sample.Target.CgroupID != "")
		if changed {
			if err := writer.Finish("unknown", now); err != nil {
				return err
			}
			writer = nil
			state = recorder.Machine{Thresholds: config.Thresholds}
		}
		if writer == nil {
			start = now
			sample.ElapsedNS = 0
			lastSync = now
			writer, err = store.Start(version, sample)
			if err != nil {
				return err
			}
			identity = sample.Target
			// Never block collection on an auxiliary sink. Copy warnings because
			// state observation below can append warnings while encoding runs.
			event := recordingDiagnostic{"recording_started", writer.Path, sample.Target.PID, append([]string(nil), sample.Warnings...)}
			select {
			case diagnosticQueue <- event:
			default:
			}
		}
		transition := state.Observe(&sample)
		forceSync := transition || len(sample.Events) > 0 || now.Sub(lastSync) >= config.SyncInterval
		if err := writer.Append(sample, forceSync); err != nil {
			return err
		}
		if forceSync {
			lastSync = now
		}
		if sample.Present != nil && !*sample.Present {
			return writer.Finish("target-disappeared", time.Now())
		}
		interval := config.Interval
		if recorder.Elevated(sample.State) {
			interval = config.ElevatedInterval
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return writer.Finish("clean", time.Now())
		case <-timer.C:
		}
	}
}
