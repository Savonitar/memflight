# Memflight

A small Linux memory flight recorder with offline, evidence-backed reports.

Memflight runs alongside an explicitly selected process, saves a bounded history
of kernel memory counters, and explains observed changes after an incident. The
initial implementation is a local prototype: `agent` and `report` work; release
acceptance and production suitability are still being validated.

## Build and use

Go 1.23 or newer is required. The project has no third-party dependencies.

```sh
go build -trimpath -o bin/memflight ./cmd/memflight
bin/memflight version
```

On Linux, select the real application PID and a dedicated persistent directory
writable by the agent's user:

```sh
bin/memflight agent --pid 1234 --output /var/lib/memflight
```

`1234` is a placeholder. The agent does not launch the application or discover it
by command line. Run it as an unprivileged user with permission to observe the
target. Manage it separately from the workload so a recorder failure cannot bring
down the workload. Placing the recorder in the same cgroup charges its memory and
associated I/O to that cgroup too.

On Linux, macOS, or Windows, read one completed incident directory offline:

```sh
bin/memflight report /var/lib/memflight/incident-REPLACE-WITH-ACTUAL-NAME
bin/memflight report --json /var/lib/memflight/incident-REPLACE-WITH-ACTUAL-NAME
```

Use `agent --help` for options. Defaults are five-second normal sampling,
one-second elevated sampling, 80/90/95 percent thresholds, five percentage points
of hysteresis, three incidents including the active recording, and 5 MiB total
logical file bytes. `--duration 60s` stops the recorder cleanly after one minute.
`--sync-interval 30s` requests synchronization at the first sample after that
interval; state transitions and counter increases request immediate synchronization.

For a reproducible disposable workload, see the [Docker experiment](examples/docker/README.md).
No application integration, deployment, upload, or monitoring backend is needed.

## What it can explain

Reports describe supported patterns using numeric evidence and heuristic confidence:
anonymous-memory growth, sampled jumps, file-cache growth, increasing swap usage,
thread/descriptor growth, observed memory recovery, and OOM-counter increases.
An increase in `oom_kill` records OOM-killed processes in its cgroup scope;
identifying the selected process as a victim or establishing the triggering limit
requires other evidence.

Sampling can miss short spikes. Anonymous memory includes many kinds of allocations;
it does not establish a native-memory leak. The collector has no request-count or
application-idleness signal. Swap usage does not by itself establish thrashing.
Reports use elapsed time within one process/cgroup identity and never join unrelated
lifetimes. Confidence levels are deterministic rules, not statistical probabilities.

Text and JSON reports include `collection_warnings`: recognized warning codes with
fixed explanations, affected-sample counts, and a flag for warnings from metadata.
This exposes hidden ancestor limits, unlimited leaf limits, unavailable or denied
metrics, parser failures and counter resets. Unknown warning text is omitted.
Coverage fields show how many samples/windows were analyzed and whether report
limits truncated pattern analysis.

## Supported observation boundary

- Linux cgroup v2 and an explicit target PID visible in the agent's PID namespace.
- The target's cgroup is located through its membership and the agent's visible
  cgroup2 mount. Unverified or inaccessible mappings omit cgroup metrics.
- `memory.current / memory.max` uses a finite, positive **leaf cgroup** limit.
  Swap is reported separately. With no readable finite limit, pressure state is
  `unknown`; process data and available cgroup data can still be recorded.
- Ancestor limits and VM-wide pressure are not evaluated. A hidden parent or VM
  can exhaust memory before the visible leaf limit. Fly Machine compatibility
  needs a separate check of the actual guest environment.
- Missing or inaccessible optional files degrade individual capabilities. Errors
  retain fixed warning codes rather than kernel contents or filesystem paths.
- Process start time and cgroup directory identity separate lifetimes. After a
  target exits, a final cgroup-only observation is possible only when the previously
  verified cgroup directory still exists with the same identity.
- Collection is sequential, not an atomic kernel snapshot. Kernel file reads are
  bounded in bytes; kernel read latency is not strictly bounded.

## Incident storage and failure behavior

Each incident has `manifest.json`, `samples.jsonl`, optional
`samples.previous.jsonl`, and a compact `summary.json` on graceful finalization.
The report is calculated from the retained samples; the agent never loads its
complete history into memory to generate a report.

Schema version 1 is experimental until the v0.1 release. The manifest records
initial collection capabilities, configuration, opaque identity, UTC timestamps,
and termination state. Samples represent missing metrics by absence and unbounded
limits in `unlimited`. Memory values use bytes, counters use counts, elapsed time
uses nanoseconds, and PSI totals use microseconds.

The directory is exclusively locked. Each retention slot receives an equal share
of the byte budget, capped at 16 MiB so it fits the offline reader; 64 KiB per slot
is reserved for metadata and atomic-write scratch space. The remaining space is
split into two sample segments. Each segment also holds at most 2,048 samples,
with a 16 KiB limit per sample line. Rotation discards the oldest segment;
retention discards the oldest timestamped incident.
The bound covers logical file sizes, including scratch files, rather than
filesystem block allocation, inode overhead, or page cache. It is a byte bound,
not a guaranteed history duration. Use a dedicated output directory; unrelated
entries and symlinked incident files are rejected by recovery/retention.

Metadata updates use synchronized temporary files and atomic rename. Samples go
directly to a file, with periodic/transition-triggered sync. A SIGKILL cannot be
handled; unsynchronized writes can be lost if the machine also fails. Mounted
persistent storage is required to preserve evidence across container recreation.
No design here guarantees survival of host loss, lost storage, or power failure.

After restart, an unfinished manifest becomes `abrupt`, with a recovery timestamp
and no invented exit timestamp or OOM cause. A partial final sample line is ignored
with a report warning; malformed complete lines fail explicitly. Readers should
use completed bundles because rotation and reading are not coordinated snapshots.

The offline reader validates the manifest/configuration, lifecycle timestamps,
sample states, known identities, numeric key allowlists, PSI ranges, unlimited
limits and increasing elapsed time across segments. It rejects duplicate JSON
keys and conflicting known identities while permitting temporarily unavailable
identity fields. JSON field names must use their documented ASCII spelling; Unicode
aliases are rejected. UTC wall-clock corrections do not invalidate increasing elapsed
times. Schema validation establishes structural consistency, not authenticity of
the supplied numbers.

Report resource limits are independent of the agent's RSS target:

| Boundary | Limit / behavior |
| --- | --- |
| Encoded input | 16 MiB across manifest and sample segments, 4,096 samples, 16 KiB per sample line. Larger or invalid input returns an error without a partial report. |
| Decoded samples | At most 56 numeric metric keys, 6 PSI averages, 12 event keys, 3 unlimited keys and 64 bounded warning strings per sample. |
| Pattern analysis | At most 32 identity/time windows and 128 findings; 8 evidence items per finding, 192 collection warnings and 32 limitations. Omitted analysis is explicitly marked `truncated`. |
| Formatted output | 256 KiB for text or JSON. Oversized output is rejected before writing to the destination. Text streams after a size preflight; JSON uses a bounded buffer. |

The recorder's new byte/count rotation limits keep newly written incidents within
the reader's capacity. Histories from older prototypes may exceed these limits and
be rejected. These bounds constrain allocations and output, not an exact process
RSS ceiling; the [validation notes](docs/validation.md) include a dense-input Linux
measurement. Run offline reports on a machine with sufficient headroom.

Disk/metadata errors stop the recorder with an error and leave unfinished metadata
for recovery. They do not invoke workload controls or unbounded retry loops. Under
storage failure, retention may already have removed an older incident when a new
recording fails to start; backup/archiving and transactional retention are outside
this prototype. Avoid reducing the budget in an existing output directory; an
incompatible retained history is rejected rather than silently truncated to fit.
Recording-start diagnostics are best-effort and use a single worker with a bounded queue.
A failed, broken, or stalled stderr sink does not stop sampling or graceful
finalization; busy diagnostics may be dropped and failed writes are not retried.
A blocked diagnostic write can retain that worker until the sink recovers or the
process exits. Report output errors still propagate normally.

## Privacy and threat model

The collector, recorder and report have no network integrations, telemetry,
automatic uploads, or listening ports. They do not open target environments,
command-line arguments, application logs, files, databases, or file-descriptor link
targets. The core never signals, pauses, attaches to, restarts, or changes limits
for the workload.

The collector reads only these kernel interfaces:

| Source | Retained observations |
| --- | --- |
| `/proc/<pid>/stat` | Numeric process start ticks; state is checked for exit, process name discarded. |
| `/proc/<pid>/cgroup` | Cgroup membership for discovery; raw path discarded. |
| `/proc/self/mountinfo` | Cgroup2 mapping for discovery; raw metadata discarded. |
| `/proc/<pid>/status` | `VmRSS`, `RssAnon`, `RssFile`, `RssShmem`, `VmSwap`, `VmSize`, `Threads`. |
| `/proc/<pid>/smaps_rollup` | `Rss`, `Pss`, `Private_Clean`, `Private_Dirty`, `Shared_Clean`, `Shared_Dirty`, `Anonymous`, `Swap`. |
| `/proc/<pid>/fd/` | Numeric directory-entry count, with no link resolution. |
| Target cgroup directory metadata | Device/inode-based opaque lifetime identifier on Linux. |
| Cgroup `memory.current`, `memory.peak`, `memory.min`, `memory.low`, `memory.high`, `memory.max` | Memory bytes or an unbounded limit. |
| Cgroup `memory.swap.current`, `memory.swap.peak`, `memory.swap.max` | Swap bytes or an unbounded limit. |
| Cgroup `memory.events`, `memory.events.local` | `low`, `high`, `max`, `oom`, `oom_kill`, `oom_group_kill` counters. |
| Cgroup `memory.stat` | `anon`, `file`, `kernel`, `kernel_stack`, `pagetables`, `percpu`, `sock`, `shmem`, `file_mapped`, `file_dirty`, `inactive_anon`, `active_anon`, `inactive_file`, `active_file`, `slab`, `slab_reclaimable`, `slab_unreclaimable`. |
| Cgroup `memory.pressure` | `some`/`full` averages and cumulative totals. |

Each pseudo-file read is capped at 128 KiB. FD enumeration uses 128-entry batches
and stops after 65,536 examined entries, omitting an incomplete count. Samples
contain allowlisted numeric kernel observations, bounded metadata, and fixed
collector warning codes; kernel `kB` is converted using 1024 bytes.

Trust the Linux kernel, configured filesystem roots, and owner of the output
directory. Root overrides are a fixture/testing feature, not a security boundary;
the collector follows filesystem symlinks. Protection against a malicious process
with the same user ID changing files concurrently is not provided. Incident files
use mode 0600 and newly created directories use 0700, subject to filesystem support.
Existing directory permissions are not changed. Bundles still contain potentially
sensitive metadata such as PIDs, timestamps, limits and resource patterns. Startup
diagnostics also include the configured incident path, PID and warning codes.
Opaque cgroup identifiers are correlation identifiers, not a guarantee of anonymity.
Handle both bundles and diagnostic logs deliberately. Use a private output directory
whose parent directories cannot be modified by other users, and never use a received
bundle directory as the agent's output: recovery and retention can modify it.

## Development and status

```sh
go test ./...
go test -race ./...
go vet ./...
go test ./internal/collector -run '^$' -bench . -benchmem
```

Parser and report tests are portable; local writer tests require Linux or macOS
file locking. Cross-compilation is not a substitute for testing on the target OS.
The [validation notes](docs/validation.md) record measured results, hardening checks,
and remaining release gates.
Provider watching, a hub, HTML reports and a metrics endpoint remain deferred.

Memflight is licensed under the Apache License 2.0; see [LICENSE](LICENSE).
