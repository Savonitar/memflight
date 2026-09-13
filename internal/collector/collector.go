// Package collector reads an explicit target's allowlisted Linux kernel metadata.
// It never opens application files, resolves descriptor links, or invokes tools.
// Configured filesystem roots must be trusted procfs/cgroup mounts or trusted
// test fixtures: reads follow symlinks and roots are not a security boundary.
package collector

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Savonitar/memflight/internal/model"
)

const (
	maxFileBytes = 128 * 1024
	maxFDEntries = 65536
)

var errTooLarge = errors.New("kernel metadata exceeds read bound")

// Collector observes one configured PID. Collect calls must not overlap.
type Collector struct {
	procRoot       string
	cgroupRoot     string
	pid            int
	lastTarget     model.Identity
	lastCgroupDir  string
	lastCgroupInfo os.FileInfo
}

// New constructs a collector. Empty roots select Linux's conventional mounts.
// Overrides permit parser tests on hosts without procfs or cgroup v2.
func New(procRoot, cgroupRoot string, pid int) (*Collector, error) {
	if pid <= 0 {
		return nil, errors.New("target PID must be positive")
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	if cgroupRoot == "" {
		cgroupRoot = "/sys/fs/cgroup"
	}
	return &Collector{procRoot: filepath.Clean(procRoot), cgroupRoot: filepath.Clean(cgroupRoot), pid: pid}, nil
}

// Collect emits only numeric observations and fixed warning codes. A process
// identity check brackets collection so a recycled PID cannot combine metrics
// from two process lifetimes in a single sample.
func (c *Collector) Collect(now time.Time, elapsed time.Duration) model.Sample {
	s := model.Sample{
		Time: now.UTC(), ElapsedNS: int64(elapsed), Target: model.Identity{PID: c.pid},
		Metrics: make(map[string]uint64), Pressure: make(map[string]float64),
	}
	procDir := filepath.Join(c.procRoot, strconv.Itoa(c.pid))
	start, state, err := readProcessIdentity(filepath.Join(procDir, "stat"))
	if err != nil {
		setIdentityFailure(&s, err)
		if s.Present != nil && !*s.Present {
			c.collectFinalCgroup(&s, 0)
		} else {
			c.lastTarget, c.lastCgroupDir, c.lastCgroupInfo = model.Identity{}, "", nil
		}
		return finish(s)
	}
	if state == "Z" || state == "X" || state == "x" {
		setIdentityFailure(&s, os.ErrNotExist)
		s.Target.StartTicks = start
		s.Warnings = append(s.Warnings, "target_exited_state")
		c.collectFinalCgroup(&s, start)
		return finish(s)
	}
	present := true
	s.Present = &present
	s.Target.StartTicks = start

	cgroupPath, cgErr := readCgroupPath(filepath.Join(procDir, "cgroup"))
	var observedCgroupDir string
	var observedCgroupInfo os.FileInfo
	if cgErr != nil {
		s.Warnings = append(s.Warnings, warningFor("target_cgroup", cgErr))
	} else {
		cgroupDir, warnings := c.resolveCgroup(cgroupPath)
		s.Warnings = append(s.Warnings, warnings...)
		if cgroupDir != "" {
			info, statErr := os.Stat(cgroupDir)
			if statErr != nil || !info.IsDir() {
				if statErr == nil {
					statErr = errors.New("not a directory")
				}
				s.Warnings = append(s.Warnings, warningFor("cgroup_directory", statErr))
			} else {
				identity, lifetime := directoryIdentity(info)
				observedCgroupDir, observedCgroupInfo = cgroupDir, info
				hash := sha256.Sum256([]byte(cgroupPath + "\x00" + identity))
				s.Target.CgroupID = hex.EncodeToString(hash[:16])
				if !lifetime {
					s.Warnings = append(s.Warnings, "cgroup_identity_path_only")
				}
				collectCgroup(cgroupDir, &s)
			}
		}
	}
	collectProcess(procDir, &s)

	verified := false
	end, endState, endErr := readProcessIdentity(filepath.Join(procDir, "stat"))
	if endErr != nil {
		clearObservations(&s)
		setIdentityFailure(&s, endErr)
		if s.Present != nil && !*s.Present {
			c.collectFinalCgroup(&s, start)
		}
	} else if end != start {
		clearObservations(&s)
		s.Warnings = append(s.Warnings, "target_changed_during_collection")
	} else if endState == "Z" || endState == "X" || endState == "x" {
		clearObservations(&s)
		setIdentityFailure(&s, os.ErrNotExist)
		s.Warnings = append(s.Warnings, "target_exited_state")
		c.collectFinalCgroup(&s, start)
	} else if cgErr == nil {
		endPath, endPathErr := readCgroupPath(filepath.Join(procDir, "cgroup"))
		if endPathErr != nil || endPath != cgroupPath {
			clearObservations(&s)
			s.Warnings = append(s.Warnings, "target_cgroup_changed_during_collection")
		} else if observedCgroupDir != "" {
			info, err := os.Stat(observedCgroupDir)
			if err != nil {
				clearObservations(&s)
				s.Warnings = append(s.Warnings, "target_cgroup_changed_during_collection")
			} else if !os.SameFile(info, observedCgroupInfo) {
				clearObservations(&s)
				s.Warnings = append(s.Warnings, "target_cgroup_changed_during_collection")
			} else {
				verified = true
			}
		}
	}
	if verified {
		c.lastTarget, c.lastCgroupDir, c.lastCgroupInfo = s.Target, observedCgroupDir, observedCgroupInfo
	} else if s.Present != nil && *s.Present {
		// An unverifiable sample cannot establish where this PID currently
		// belongs. Do not carry an older scope into a later exit observation.
		c.lastTarget, c.lastCgroupDir, c.lastCgroupInfo = model.Identity{}, "", nil
	}
	return finish(s)
}

// collectFinalCgroup preserves exit-time OOM counters without reading process
// metrics after disappearance. The directory must still be the exact lifetime
// captured by a previous fully verified sample, including after these reads.
func (c *Collector) collectFinalCgroup(s *model.Sample, start uint64) {
	if c.lastCgroupInfo == nil || (start != 0 && start != c.lastTarget.StartTicks) {
		return
	}
	s.Target = c.lastTarget
	info, err := os.Stat(c.lastCgroupDir)
	if err != nil || !os.SameFile(info, c.lastCgroupInfo) {
		s.Warnings = append(s.Warnings, "cached_cgroup_identity_unavailable_or_changed")
		return
	}
	collectCgroup(c.lastCgroupDir, s)
	info, err = os.Stat(c.lastCgroupDir)
	if err != nil || !os.SameFile(info, c.lastCgroupInfo) {
		clearObservations(s)
		s.Warnings = append(s.Warnings, "cached_cgroup_identity_unavailable_or_changed")
	}
}

func clearObservations(s *model.Sample) {
	s.Metrics = make(map[string]uint64)
	s.Pressure = make(map[string]float64)
	s.Unlimited = nil
}

func setIdentityFailure(s *model.Sample, err error) {
	if errors.Is(err, os.ErrNotExist) {
		present := false
		s.Present = &present
		s.Warnings = append(s.Warnings, "target_missing")
	} else {
		// Permission errors or malformed metadata do not prove disappearance.
		s.Present = nil
		s.Warnings = append(s.Warnings, warningFor("target_identity", err))
	}
}

func finish(s model.Sample) model.Sample {
	sort.Strings(s.Warnings)
	s.Warnings = unique(s.Warnings)
	sort.Strings(s.Unlimited)
	return s
}

func unique(values []string) []string {
	if len(values) == 0 {
		return values
	}
	n := 1
	for _, value := range values[1:] {
		if value != values[n-1] {
			values[n] = value
			n++
		}
	}
	return values[:n]
}

func warningFor(prefix string, err error) string {
	switch {
	case errors.Is(err, os.ErrPermission):
		return prefix + "_permission_denied"
	case errors.Is(err, os.ErrNotExist):
		return prefix + "_unavailable"
	case errors.Is(err, errTooLarge):
		return prefix + "_too_large"
	default:
		return prefix + "_invalid_or_unreadable"
	}
}

func readBounded(filename string) (string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxFileBytes {
		return "", errTooLarge
	}
	return string(data), nil
}

func readProcessIdentity(filename string) (uint64, string, error) {
	data, err := readBounded(filename)
	if err != nil {
		return 0, "", err
	}
	// comm (field 2) can itself contain spaces and parentheses. Discard all
	// of it; only numeric starttime (field 22) becomes an observation.
	open := strings.IndexByte(data, '(')
	close := strings.LastIndexByte(data, ')')
	if open < 0 || close <= open {
		return 0, "", errors.New("invalid process identity")
	}
	fields := strings.Fields(data[close+1:])
	if len(fields) < 20 || len(fields[0]) != 1 || !strings.Contains("RSDZTWtXxKPI", fields[0]) {
		return 0, "", errors.New("incomplete process identity")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	return ticks, fields[0], err
}

func readCgroupPath(filename string) (string, error) {
	data, err := readBounded(filename)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(data, "\n") {
		if strings.HasPrefix(line, "0::") {
			value := strings.TrimPrefix(line, "0::")
			if !safeHierarchyPath(value) {
				return "", errors.New("unreachable cgroup path")
			}
			return path.Clean(value), nil
		}
	}
	return "", errors.New("cgroup v2 membership unavailable")
}

func safeHierarchyPath(value string) bool {
	if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\x00\r\n\\") {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == ".." {
			return false
		}
	}
	return true
}

// resolveCgroup maps membership from the target process, never the agent's own
// membership. mountinfo's root permits a bind-mounted hierarchy subtree. A
// caller-provided root relocates that mount for fixtures or container layouts.
func (c *Collector) resolveCgroup(targetPath string) (string, []string) {
	var warnings []string
	mountRoot := "/"
	data, err := readBounded(filepath.Join(c.procRoot, "self", "mountinfo"))
	if err != nil {
		return "", []string{warningFor("cgroup_mountinfo", err), "cgroup_mount_mapping_unverified"}
	} else {
		bestMatch := 0
		matchCount := 0
		for _, line := range strings.Split(data, "\n") {
			left, right, ok := strings.Cut(line, " - ")
			fields, types := strings.Fields(left), strings.Fields(right)
			if !ok || len(fields) < 6 || len(types) == 0 || types[0] != "cgroup2" {
				continue
			}
			point := unescapeMount(fields[4])
			match := 0
			if point == "/sys/fs/cgroup" {
				match = 1
			}
			if filepath.Clean(point) == c.cgroupRoot {
				match = 2
			}
			if match == 0 || match < bestMatch {
				continue
			}
			root := unescapeMount(fields[3])
			if !safeHierarchyPath(root) {
				continue
			}
			if match > bestMatch {
				mountRoot, bestMatch, matchCount = path.Clean(root), match, 1
			} else {
				matchCount++
			}
		}
		if bestMatch == 0 {
			return "", []string{"cgroup_mount_mapping_unverified"}
		}
		if matchCount != 1 {
			return "", []string{"cgroup_mount_mapping_ambiguous"}
		}
	}
	if mountRoot != "/" {
		warnings = append(warnings, "cgroup_ancestor_limits_may_be_hidden")
		if targetPath == mountRoot {
			targetPath = "/"
		} else if strings.HasPrefix(targetPath, mountRoot+"/") {
			targetPath = strings.TrimPrefix(targetPath, mountRoot)
		} else {
			// A membership outside this mount cannot be mapped safely. Do not
			// silently collect the agent's root cgroup in its place.
			return "", append(warnings, "target_cgroup_outside_visible_mount")
		}
	}
	if targetPath != "/" {
		warnings = append(warnings, "cgroup_ancestor_limits_not_evaluated")
	} else {
		// A cgroup namespace can expose a subtree as '/'. The mount metadata
		// cannot prove that this visible root is the host hierarchy root.
		warnings = append(warnings, "cgroup_ancestor_limits_may_be_hidden")
	}
	return filepath.Join(c.cgroupRoot, filepath.FromSlash(strings.TrimPrefix(targetPath, "/"))), warnings
}

func unescapeMount(value string) string {
	return strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`).Replace(value)
}

var scalarFiles = []string{
	"memory.current", "memory.peak", "memory.min", "memory.low", "memory.high", "memory.max",
	"memory.swap.current", "memory.swap.peak", "memory.swap.max",
}

var statFields = map[string]bool{
	"anon": true, "file": true, "kernel": true, "kernel_stack": true,
	"pagetables": true, "percpu": true, "sock": true, "shmem": true,
	"file_mapped": true, "file_dirty": true, "inactive_anon": true,
	"active_anon": true, "inactive_file": true, "active_file": true,
	"slab": true, "slab_reclaimable": true, "slab_unreclaimable": true,
}

var eventFields = map[string]bool{
	"low": true, "high": true, "max": true, "oom": true, "oom_kill": true, "oom_group_kill": true,
}

func collectCgroup(dir string, s *model.Sample) {
	for _, name := range scalarFiles {
		key := "cgroup." + name
		data, err := readBounded(filepath.Join(dir, name))
		if err != nil {
			s.Warnings = append(s.Warnings, warningFor(strings.ReplaceAll(key, ".", "_"), err))
			continue
		}
		value := strings.TrimSpace(data)
		if value == "max" && (strings.HasSuffix(name, ".max") || name == "memory.high") {
			s.Unlimited = append(s.Unlimited, key)
			if name == "memory.max" {
				s.Warnings = append(s.Warnings, "cgroup_memory_limit_unlimited")
			}
			continue
		}
		parsed, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			s.Warnings = append(s.Warnings, strings.ReplaceAll(key, ".", "_")+"_invalid")
			continue
		}
		s.Metrics[key] = parsed
	}
	for _, spec := range []struct {
		name   string
		fields map[string]bool
	}{{"memory.stat", statFields}, {"memory.events", eventFields}, {"memory.events.local", eventFields}} {
		data, err := readBounded(filepath.Join(dir, spec.name))
		prefix := "cgroup." + spec.name
		if err != nil {
			s.Warnings = append(s.Warnings, warningFor(strings.ReplaceAll(prefix, ".", "_"), err))
			continue
		}
		parseCounters(data, prefix, spec.fields, s)
	}
	data, err := readBounded(filepath.Join(dir, "memory.pressure"))
	if err != nil {
		s.Warnings = append(s.Warnings, warningFor("cgroup_memory_pressure", err))
	} else {
		parsePressure(data, s)
	}
}

func parseCounters(data, prefix string, allow map[string]bool, s *model.Sample) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || !allow[fields[0]] {
			continue
		}
		if len(fields) != 2 {
			s.Warnings = append(s.Warnings, strings.ReplaceAll(prefix, ".", "_")+"_invalid")
			continue
		}
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			s.Warnings = append(s.Warnings, strings.ReplaceAll(prefix, ".", "_")+"_invalid")
			continue
		}
		s.Metrics[prefix+"."+fields[0]] = value
	}
}

func parsePressure(data string, s *model.Sample) {
	for _, line := range strings.Split(data, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "some" && fields[0] != "full") {
			continue
		}
		prefix := "cgroup.memory.pressure." + fields[0] + "."
		for _, field := range fields[1:] {
			name, value, ok := strings.Cut(field, "=")
			if !ok {
				s.Warnings = append(s.Warnings, "cgroup_memory_pressure_invalid")
				continue
			}
			if name == "total" {
				parsed, err := strconv.ParseUint(value, 10, 64)
				if err != nil {
					s.Warnings = append(s.Warnings, "cgroup_memory_pressure_invalid")
				} else {
					s.Metrics[prefix+name] = parsed
				}
			} else if name == "avg10" || name == "avg60" || name == "avg300" {
				parsed, err := strconv.ParseFloat(value, 64)
				if err != nil || math.IsNaN(parsed) || math.IsInf(parsed, 0) || parsed < 0 || parsed > 100 {
					s.Warnings = append(s.Warnings, "cgroup_memory_pressure_invalid")
				} else {
					s.Pressure[prefix+name] = parsed
				}
			}
		}
	}
}

var statusFields = map[string]bool{
	"VmRSS": true, "RssAnon": true, "RssFile": true, "RssShmem": true,
	"VmSwap": true, "VmSize": true, "Threads": true,
}

var smapsFields = map[string]bool{
	"Rss": true, "Pss": true, "Private_Clean": true, "Private_Dirty": true,
	"Shared_Clean": true, "Shared_Dirty": true, "Anonymous": true, "Swap": true,
}

func collectProcess(dir string, s *model.Sample) {
	for _, spec := range []struct {
		name   string
		prefix string
		fields map[string]bool
	}{{"status", "proc.status", statusFields}, {"smaps_rollup", "proc.smaps", smapsFields}} {
		data, err := readBounded(filepath.Join(dir, spec.name))
		if err != nil {
			s.Warnings = append(s.Warnings, warningFor("proc_"+spec.name, err))
			continue
		}
		parseProcessFields(data, spec.prefix, spec.fields, s)
	}
	count, err := countFDs(filepath.Join(dir, "fd"))
	if err != nil {
		s.Warnings = append(s.Warnings, warningFor("proc_fd_count", err))
	} else {
		s.Metrics["proc.fd_count"] = count
	}
}

func parseProcessFields(data, prefix string, allow map[string]bool, s *model.Sample) {
	for _, line := range strings.Split(data, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !allow[name] {
			continue
		}
		fields := strings.Fields(value)
		isCount := prefix == "proc.status" && name == "Threads"
		validUnits := (isCount && len(fields) == 1) || (!isCount && len(fields) == 2 && fields[1] == "kB")
		if !validUnits {
			s.Warnings = append(s.Warnings, strings.ReplaceAll(prefix, ".", "_")+"_invalid")
			continue
		}
		parsed, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil || (!isCount && parsed > math.MaxUint64/1024) {
			s.Warnings = append(s.Warnings, strings.ReplaceAll(prefix, ".", "_")+"_invalid")
			continue
		}
		if !isCount {
			parsed *= 1024
		}
		s.Metrics[prefix+"."+name] = parsed
	}
}

func countFDs(dir string) (uint64, error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return countFDNames(f.Readdirnames)
}

func countFDNames(readNames func(int) ([]string, error)) (uint64, error) {
	var count, examined uint64
	for {
		// Readdirnames does not stat entries or resolve their symlink targets.
		names, err := readNames(128)
		examined += uint64(len(names))
		for _, name := range names {
			if _, parseErr := strconv.ParseUint(name, 10, 64); parseErr == nil {
				count++
			}
		}
		if examined > maxFDEntries {
			return 0, errTooLarge
		}
		if err == io.EOF {
			return count, nil
		}
		if err != nil {
			return 0, fmt.Errorf("descriptor enumeration: %w", err)
		}
	}
}
