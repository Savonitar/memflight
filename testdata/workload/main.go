// Command workload is a bounded synthetic workload for disposable, memory-limited
// Linux containers. It is not an application benchmark and must not be used as a
// host OOM generator. See examples/docker/README.md before running it.
package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"
)

const (
	mib              = 1024 * 1024
	pressureLimitMiB = 384
	recoveryLimitMiB = 64
	maxStepMiB       = 64
	maxDuration      = 5 * time.Minute
)

func main() {
	mode := flag.String("mode", "recovery", "workload mode: gradual, spike, or recovery")
	stepMiB := flag.Int("step", 4, "MiB allocated per gradual/recovery step (1..64)")
	interval := flag.Duration("interval", 200*time.Millisecond, "delay between gradual/recovery steps (1ms..5m)")
	hold := flag.Duration("hold", 10*time.Second, "hold after allocation, or after recovery (0..5m)")
	flag.Usage = func() {
		fmt.Fprintln(flag.CommandLine.Output(), "Disposable test workload: run only in a container with --memory 256m.")
		fmt.Fprintln(flag.CommandLine.Output(), "Total live allocations are capped at 384 MiB (pressure) or 64 MiB (recovery).")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 0 {
		fail("unexpected positional arguments")
	}
	if *mode != "gradual" && *mode != "spike" && *mode != "recovery" {
		fail("mode must be gradual, spike, or recovery")
	}
	if *stepMiB < 1 || *stepMiB > maxStepMiB {
		fail("step must be between 1 and 64 MiB")
	}
	if *interval < time.Millisecond || *interval > maxDuration {
		fail("interval must be between 1ms and 5m")
	}
	if *hold < 0 || *hold > maxDuration {
		fail("hold must be between 0 and 5m")
	}

	fmt.Fprintf(os.Stderr, "Synthetic workload: mode=%s pid=%d; use a disposable --memory 256m container only.\n", *mode, os.Getpid())
	switch *mode {
	case "spike":
		// Give the recorder time to start, then touch pages without a paced ramp.
		time.Sleep(2 * time.Second)
		blocks := allocate(pressureLimitMiB, pressureLimitMiB, 0)
		time.Sleep(*hold)
		runtime.KeepAlive(blocks)
	case "gradual":
		blocks := allocate(pressureLimitMiB, *stepMiB, *interval)
		time.Sleep(*hold)
		runtime.KeepAlive(blocks)
	case "recovery":
		// Keep the high-water level visible before dropping references. The
		// post-recovery hold gives the recorder time to observe released memory.
		blocks := allocate(recoveryLimitMiB, *stepMiB, *interval)
		time.Sleep(2 * time.Second)
		runtime.KeepAlive(blocks)
		blocks = nil
		runtime.GC()
		debug.FreeOSMemory()
		fmt.Fprintln(os.Stderr, "released_allocations=true")
		time.Sleep(*hold)
	}
}

// allocate retains and touches a fixed total; it never grows indefinitely, even
// if accidentally run without a cgroup limit. All callers use constant totals.
func allocate(totalMiB, stepMiB int, interval time.Duration) [][]byte {
	blocks := make([][]byte, 0, (totalMiB+stepMiB-1)/stepMiB)
	pageSize := os.Getpagesize()
	for allocatedMiB := 0; allocatedMiB < totalMiB; {
		chunkMiB := min(stepMiB, totalMiB-allocatedMiB)
		block := make([]byte, chunkMiB*mib)
		for offset := 0; offset < len(block); offset += pageSize {
			block[offset] = 1
		}
		block[len(block)-1] = 1
		blocks = append(blocks, block)
		allocatedMiB += chunkMiB
		fmt.Fprintf(os.Stderr, "allocated_mib=%d\n", allocatedMiB)
		if allocatedMiB < totalMiB && interval > 0 {
			time.Sleep(interval)
		}
	}
	return blocks
}

func fail(message string) {
	fmt.Fprintln(os.Stderr, "workload:", message)
	os.Exit(2)
}
