# Disposable Linux recorder experiment

This example runs the agent and a synthetic target in the same memory-limited
container, as the same non-root user. A shell starts the target and recorder as
separate children, passing the target's explicit PID to the recorder. It waits for
the target before reaping the recorder and exits with the target's status, so a
recorder failure does not cause the shell to stop a running target. Incident output
is bind-mounted outside the container so it remains available after the container
is removed. Neither binary needs network access, extra capabilities, or application
data.

The synthetic workload is only for disposable containers with an explicit
`--memory 256m` limit. Do not run it directly on the host. Its total retained
allocations are bounded even without a limit, but this is not a host-memory test or
a production workload.

## Build locally

From the repository root, with Go 1.23 or newer, run these commands as a normal
non-root user. They build static Linux binaries and create an empty output directory
in temporary storage. The architecture must match the Docker engine; the default
below assumes a local engine with the same architecture as the Go installation.

```sh
demo_dir="$(mktemp -d "${TMPDIR:-/tmp}/memflight-demo.XXXXXX")"
mkdir -p "$demo_dir/bin" "$demo_dir/incidents"
demo_arch="$(go env GOARCH)"
CGO_ENABLED=0 GOOS=linux GOARCH="$demo_arch" go build -trimpath -o "$demo_dir/bin/memflight" ./cmd/memflight
CGO_ENABLED=0 GOOS=linux GOARCH="$demo_arch" go build -trimpath -o "$demo_dir/bin/workload" ./testdata/workload
```

The workload resides under `testdata`, so build it explicitly: `go build ./...`
does not select that directory. It uses only the Go standard library.

Use an existing local Alpine image or obtain one separately before running the
experiment. The default image name is configurable:

```sh
demo_image="${MEMFLIGHT_TEST_IMAGE:-alpine:3.22}"
```

## Run one scenario

Start with `recovery`. Each scenario should use its own empty output directory, or
the configured recorder retention policy may remove earlier experiments.

```sh
docker run --rm --name memflight-demo \
  --pull never \
  --memory 256m --memory-swap 512m \
  --cpus 1 --pids-limit 128 \
  --network none --cap-drop ALL \
  --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" --read-only \
  --mount "type=bind,src=$demo_dir/bin,dst=/opt/memflight,readonly" \
  --mount "type=bind,src=$demo_dir/incidents,dst=/incidents" \
  --env WORKLOAD_MODE=recovery \
  "$demo_image" sh -c '
    /opt/memflight/workload --mode "$WORKLOAD_MODE" --hold 8s &
    target_pid=$!
    /opt/memflight/memflight agent \
      --pid "$target_pid" --output /incidents \
      --interval 250ms --elevated-interval 100ms --sync-interval 1s \
      --max-bytes 2097152 --retention 2 --duration 45s &
    recorder_pid=$!
    target_status=0
    wait "$target_pid" || target_status=$?
    wait "$recorder_pid" || printf "recorder exited with status %s\n" "$?" >&2
    exit "$target_status"
  '
```

This shell is a disposable test harness, not a production supervisor. It does not
implement graceful forwarding of host-stop signals to its children. Production
deployment needs an init/supervisor with deliberate signal forwarding and child
reaping, configured so recorder failure cannot stop the workload. The collector
itself never signals the target. The parent/child arrangement has been exercised
with recovery and OOM workloads; see the [validation notes](../../docs/validation.md)
for results and the test harness's exit-status handling.

The short sampling intervals here are for observing a controlled experiment; they
are not measured production defaults. The collector should degrade individual
capabilities when kernel fields or process information are not readable.

`--memory-swap 512m` sets a **512 MiB combined RAM-and-swap limit**, giving up to
256 MiB swap alongside the 256 MiB physical limit when the Docker host supports
swap. It does not mean 512 MiB additional swap. A 384 MiB allocation may fit when
swap is available, so this configuration is not guaranteed to produce an OOM.

For a controlled no-swap OOM test, change only the combined limit to
`--memory-swap 256m` and select `gradual` or `spike`. Preserve `--memory 256m` in
every run. Inspect which process died and the recorded event evidence rather than
treating a container exit code alone as proof of the cause. A whole-group kill may
terminate the recorder too; its final sample and graceful finalization are not
guaranteed.

## Workload modes

| Mode | Behavior | Intended observation |
| --- | --- | --- |
| `recovery` | Ramp to 64 MiB, hold two seconds, release references, run GC and return memory to the OS, then hold. | Growth followed by observable recovery. |
| `gradual` | Allocate and touch up to 384 MiB in paced steps, then hold. | Gradual growth and, with the strict no-swap limit, possible OOM evidence. |
| `spike` | Wait two seconds, rapidly allocate and touch up to 384 MiB, then hold. | Sampling gaps around a rapid allocation or abrupt kill. |

`--step` is MiB per gradual/recovery step, defaults to 4, and accepts 1–64.
`--interval` defaults to `200ms` and accepts `1ms` through `5m`; `--hold` defaults
to `10s` and accepts zero through `5m`. Spike ignores the step and interval values.
Pressure modes stop allocating at 384 MiB, and recovery stops at 64 MiB. Workload
diagnostic output contains only mode, PID, and allocation progress; the agent does
not need to collect those messages.

## Read the incident offline

Build the native report binary on the host, then pass an actual incident directory
created under `$demo_dir/incidents`:

```sh
go build -trimpath -o "$demo_dir/memflight-report" ./cmd/memflight
"$demo_dir/memflight-report" report "$demo_dir/incidents/incident-REPLACE-WITH-ACTUAL-NAME"
"$demo_dir/memflight-report" report --json "$demo_dir/incidents/incident-REPLACE-WITH-ACTUAL-NAME"
```

Keep the output directory for a restart/recovery experiment. Bind mounting makes
it independent of container deletion; it does not establish survival of host loss,
power failure, or a lost temporary directory. Validate flush/rotation behavior
and partial-record recovery for your deployment; the remaining filesystem-fault
checks are listed in the validation notes below.

These commands are a local test recipe. The [validation notes](../../docs/validation.md)
record completed experiments and remaining gates. Record the image, architecture,
kernel/cgroup capabilities, swap availability, actual results, and any data gaps
when running them on another environment.
