# Prototype validation — 2026-09-06

These are local prototype results, not release certification. No production
application, Fly deployment, repository publication, or private application data
was involved. The remaining release and production checks are listed below.

## Environment and method

- Build/test host: macOS arm64, Apple M4 Pro.
- Compiler: official Go 1.27.1 darwin/arm64 archive, SHA-256 verified against Go's
  download metadata. Module minimum is Go 1.23; minimum-version execution is pending.
- Linux runtime: local Docker Engine 29.1.3, aarch64,
  kernel `6.12.54-linuxkit`, cgroup v2.
- Image: `alpine:3.22`, downloaded index digest
  `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce`.
- Agent: static Linux arm64 build with `CGO_ENABLED=0`, `-trimpath`,
  `-ldflags '-s -w'`; all runs used a non-root UID, read-only root filesystem,
  no network, no added capabilities, no-new-privileges, a one-CPU cap, and
  128-process cap. Only synthetic binaries and temporary incident output were mounted.
- Recovery used 256 MiB RAM / 512 MiB combined RAM+swap. OOM tests used
  256 MiB RAM / 256 MiB combined limit, explicitly disabling swap for that cgroup.
  Swap usage remained zero in these recordings; meaningful swap-pressure behavior
  has not been validated.
- Resource measurements used Alpine `/usr/bin/time -v` around the agent only.
  Maximum RSS is a peak, not a steady-state sample or an idle growth slope.
  CPU percentages below are calculated as `(user + system) / elapsed * 100`;
  timer precision and short runs limit accuracy.

The [Docker guide](../examples/docker/README.md) describes the reproduction.
The final recovery and pressure tests used a shell parent with separate target and
recorder children. It reaped both independently; the recorder's exit did not decide
the target's lifetime. The guide exits with the target's status; validation harnesses
printed both statuses and returned the recorder status for inspecting the result.

## Completed checks

| Check | Result |
| --- | --- |
| `go test ./...` | Passed on macOS arm64. |
| `go test -race ./...` | Passed on macOS arm64. |
| `go vet ./...` | Passed. |
| Collector and incident test binaries on Linux arm64 | Passed as non-root in the capped container. Includes actual permission-denied reads and `/dev/full` write-failure handling. |
| Linux arm64 and amd64 CLI builds | Passed. amd64 execution/performance is not established by cross-compilation. |
| Windows amd64 CLI and collector-test cross-compilation | Passed. Windows execution is pending. |
| Rotation, retention, abrupt/partial recovery, locking | Fixture tests passed. |
| Storage safety | Symlink rejection, hard-linked scratch preservation, foreign-file preservation and nonempty lock rejection passed. |
| Process/cgroup boundaries | PID reuse, cgroup replacement/discovery, terminal cgroup-only counters and monotonic-time boundaries passed. |
| Report behavior, initial implementation | Pattern regressions and empty/insufficient-evidence text/JSON goldens passed; offline native reports consumed Linux bundles. Representative nonempty goldens were added during later hardening. |

## Linux scenarios

Only the final recording for each repeated scenario is summarized below. The byte
counts include the files inside that incident directory. All output stayed below
its configured total limit; fixture rotation tests also exercise sustained writes
and retention beyond the count limit.

| Scenario | Samples / logical bytes | Observed result |
| --- | --- | --- |
| Recovery, 250 ms normal / 100 ms elevated | 52 / 123,790 | Memory recovery observed while target remained alive. Target and recorder both exited 0. Manifest says `target-disappeared`, since the observer cannot establish the target's exit code. |
| Gradual allocation to OOM, 250 ms / 100 ms | 66 / 157,168 | Target exit 137, recorder exit 0; local OOM-kill counter increased by 1. Report preserves gradual anonymous growth and near-limit usage. Memory released at exit is excluded from workload recovery. |
| Rapid allocation to OOM, default 5 s / 1 s | 2 / 7,421 | Target exit 137, recorder exit 0. OOM-counter evidence survived; polling missed the spike's growth trajectory. Report does not invent a sampled spike. |
| Recorder/container SIGKILL, then new container using the same output | 7 / 19,073 in recovered incident | Prior history remained readable. Manifest became `abrupt` with a recovery timestamp, no invented end time, and no OOM finding. The subsequent recording finalized `clean`. |
| Idle sleep target, 5 s / 1 s, 60 s duration | 12 / 30,668 | Clean recorder finalization; no supported growth pattern. |

The OOM victim and exit status above are known from the controlled test harness.
The report deliberately claims only what its own samples establish. A cgroup
counter alone cannot identify the victim or distinguish every triggering limit.

See [example-report.txt](example-report.txt) for the gradual-OOM recording analyzed
by the current report implementation, including collection warnings added during
later hardening. The underlying recording and resource measurements below predate
those changes.

## Initial resource measurements

| Run | Elapsed | User / system CPU | Approx. one-core CPU | Peak RSS |
| --- | --- | --- | --- | --- |
| Idle, final binary, default sampling | 60.02 s | 0.00 / 0.01 s | 0.02% | 9,368 KiB = 9.15 MiB |
| Gradual OOM, final binary, 250 ms / 100 ms | 12.59 s | 0.03 / 0.09 s | 0.95% | 11,516 KiB = 11.25 MiB |

An earlier 60-second idle run measured 7,128 KiB (6.96 MiB) maximum RSS; an earlier
pressure run measured 11,696 KiB (11.42 MiB). Short-run variation is material.
The final idle peak is below 10 MiB, but these runs do **not** establish the
30-minute steady-state target or the <=1 MiB growth requirement. Faster sampling
exceeded 10 MiB peak RSS and consumed more CPU than default idle collection. The
published CPU target applies at five-second sampling, not this 100–250 ms test.
Memory associated with filesystem cache/kernel accounting is outside process RSS.

The following fixture benchmarks ran on macOS, not Linux, for 100 iterations:

| Benchmark | Time/op | Allocated bytes/op | Allocations/op |
| --- | --- | --- | --- |
| Full fixture collection | 223,521 ns | 34,224 | 336 |
| Sample JSON encoding (ten metrics) | 1,810 ns | 940 | 15 |

These measure a specific fixture and serialization workload. They do not measure
Linux procfs costs, application overhead, or steady-state memory residency.

## Still unverified

- 30-minute idle RSS growth; repeated/default-interval pressure runs and overhead
  comparison against the same workload without the recorder.
- Linux amd64 execution and measured overhead; Windows execution; minimum Go version.
- Fly guest cgroup/VM limits and storage lifecycle; no Fly or production integration
  has been performed.
- Active swap pressure, file-cache pressure, large live descriptor/thread counts,
  and real runtime workloads beyond the synthetic Go allocator.
- Whole-cgroup OOM killing the recorder together with the target. SIGKILL recovery
  demonstrates process/container loss, not every OOM ordering or machine failure.
- Power failure, filesystem/device exhaustion and failure ordering during metadata
  operations. `/dev/full` verifies an append failure, not the entire disk-full lifecycle.
- Long-term retention/rotation under concurrency and filesystem faults. Logical
  byte accounting does not bound allocated filesystem blocks or inode metadata.
- Ancestor-limit/VM-wide pressure analysis, calibrated diagnostic accuracy, and
  release packaging/security documentation and CI.

## Report hardening validation

Warning propagation, input validation, output bounds, and diagnostics resilience
were checked with the same Go 1.27.1/macOS arm64 and Linux arm64 Docker environment.
The original agent resource measurements above were not rerun and remain short
prototype runs.

| Check | Result |
| --- | --- |
| `go test ./...`, `go test -race ./...`, `go vet ./...` | Passed after the hardening changes. |
| Nonempty report goldens | Complete OOM/growth/collection-warning text and JSON fixtures now pass, alongside the empty goldens. |
| Warning visibility/privacy | Known sample, manifest and reader warnings are visible; unknown injected text is omitted. CLI integration tests verify the complete path. |
| Schema integrity / reader bounds | Exact 16 MiB aggregate, 4,096 samples, 16 KiB line boundaries; sparse oversized files; duplicate JSON keys; invalid fields, identities and lifecycle data; rotation chronology and legitimate unavailable fields all tested. |
| Analyzer / output bounds | Many-window and finding/evidence/warning limits, coverage/truncation, oversized output and JSON escape expansion tested. Budget rejection writes no destination output. |
| Recorder/reader compatibility | Small-sample histories rotate at the count limit, and large configured disk budgets still produce reportable incidents. |
| Diagnostics resilience | A failing writer and a real subprocess with a closed fd 2 pipe both preserve recording. No diagnostic retry loop. |
| Metadata short write | An incomplete byte count returns `io.ErrShortWrite` and prevents metadata publication. |
| Linux arm64 storage and CLI tests | Passed as non-root in a 128 MiB/no-swap container, including real broken stderr and `/dev/full`. |
| Existing Linux bundles | All nine prior synthetic Linux recordings passed the stricter reader and produced untruncated reports with ancestor-limit warnings. |
| Cross-builds | Linux arm64/amd64 and Windows amd64 CLI builds passed. Runtime/production gates listed above remain open. |

A separate dense synthetic input exercised all 4,096 sample slots, 56 numeric
metric keys, 6 PSI averages, 12 event keys and 64 bounded warning entries per
sample. Its combined manifest/sample size was **16,533,838 bytes**. It deliberately
contains synthetic counter values and unrecognized warning text; it is a resource
and privacy test, not an actual OOM recording.

Linux arm64 `report --json` completed under a 128 MiB/no-swap limit, no network,
read-only mounts and non-root UID. `/usr/bin/time -v` measured **56,272 KiB
(54.95 MiB) peak RSS**, 0.25 seconds elapsed, 0.23 seconds user CPU and 0.01 seconds
system CPU. The output omitted the synthetic warning text. This single
near-limit-input result demonstrates the bounded configuration on this platform;
it is not a universal RSS ceiling or an agent-overhead measurement.

## Security hardening follow-up

Subsequent fixes added strict JSON field/type validation, bounded recording
diagnostics, recovery warning bounds, and invalid-manifest rejection before
retention. Unit/race tests and vet passed; two bounded fuzz campaigns passed about
3.1 million generated executions. Updated Linux arm64 incident/CLI tests also passed
as non-root without network access in a 256 MiB/no-swap container, including real
broken-stderr and `/dev/full` cases. The resource measurements above predate these
fixes and do not measure the added diagnostic worker.
