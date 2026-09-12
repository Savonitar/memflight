package incident

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"github.com/Savonitar/memflight/internal/model"
)

const metadataLimit = 16 * 1024
const metadataReserve = 64 * 1024
const maxSampleBytes = MaxReadLineBytes

var incidentName = regexp.MustCompile(`^incident-[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-[0-9a-f]{12}$`)

// Store owns a dedicated directory and a nonblocking OS lock. The configured
// byte bound includes all retained sessions, metadata and atomic-write scratch.
// Each retained slot receives an equal quota; active history uses two segments.
type Store struct {
	root   string
	config Config
	lock   *os.File
	active *Writer
}

type Writer struct {
	store          *Store
	Path           string
	manifest       Manifest
	file           *os.File
	size           int64
	segmentSamples int
	segmentLimit   int64
	samples        uint64
	rotations      uint64
	lastState      string
}

func (c Config) Validate() error {
	if c.Interval < 10*time.Millisecond || c.ElevatedInterval < 10*time.Millisecond || c.ElevatedInterval > c.Interval || c.SyncInterval < c.Interval {
		return errors.New("require intervals >= 10ms, elevated <= normal, and sync >= normal")
	}
	if c.Retention < 1 || c.Retention > 100 || c.MaxBytes < int64(c.Retention)*128*1024 || c.MaxBytes > 64*1024*1024 {
		return errors.New("require 1..100 retained incidents and 128 KiB per incident within a 64 MiB total bound")
	}
	return c.Thresholds.Validate()
}

func Open(root string, config Config) (*Store, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, errors.New("cannot create output directory")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("output must be a dedicated real directory")
	}
	lock, err := acquireLock(filepath.Join(root, ".writer.lock"))
	if err != nil {
		return nil, err
	}
	s := &Store{root: root, config: config, lock: lock}
	if err := s.recover(); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) directories() ([]string, error) {
	dir, err := os.Open(s.root)
	if err != nil {
		return nil, errors.New("cannot inspect output directory")
	}
	defer dir.Close()
	var names []string
	for {
		entries, readErr := dir.ReadDir(32)
		for _, entry := range entries {
			if entry.Name() == ".writer.lock" && entry.Type().IsRegular() {
				continue
			}
			if !incidentName.MatchString(entry.Name()) || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return nil, errors.New("output contains unrecognized entries; use a dedicated directory")
			}
			names = append(names, entry.Name())
			if len(names) > 100 {
				return nil, errors.New("too many incident directories")
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, errors.New("cannot inspect output directory")
		}
	}
	sort.Strings(names)
	return names, nil
}

// Check every entry before recovery or retention can modify a directory. Never
// traverse arbitrary directories or follow file symlinks during housekeeping.
func validateDirectory(path string) (int64, error) {
	dir, err := os.Open(path)
	if err != nil {
		return 0, errors.New("cannot inspect incident directory")
	}
	defer dir.Close()
	entries, err := dir.ReadDir(7)
	if err != nil && err != io.EOF {
		return 0, errors.New("cannot inspect incident directory")
	}
	if len(entries) > 5 {
		return 0, errors.New("unrecognized incident contents")
	}
	var size int64
	for _, entry := range entries {
		switch entry.Name() {
		case "manifest.json", "summary.json", "samples.jsonl", "samples.previous.jsonl", "metadata.tmp":
		default:
			return 0, errors.New("unrecognized incident contents")
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return 0, errors.New("incident entries must be regular files")
		}
		size += info.Size()
	}
	return size, nil
}

func (s *Store) recover() error {
	names, err := s.directories()
	if err != nil {
		return err
	}
	var total int64
	for _, name := range names {
		size, err := validateDirectory(filepath.Join(s.root, name))
		if err != nil {
			return err
		}
		total += size
	}
	// Refuse to silently truncate data created under a larger budget.
	if total > s.config.MaxBytes-metadataLimit {
		return errors.New("existing recordings exceed available budget; use a new output directory or larger limit")
	}
	for _, name := range names {
		path := filepath.Join(s.root, name)
		m, err := readManifest(path)
		if errors.Is(err, os.ErrNotExist) {
			// mkdir may have persisted before the first atomic manifest rename.
			entries, readErr := os.ReadDir(path)
			if readErr != nil {
				return errors.New("cannot inspect interrupted initialization")
			}
			for _, e := range entries {
				if e.Name() != "metadata.tmp" {
					return errors.New("incident is missing its manifest")
				}
			}
			if err := os.RemoveAll(path); err != nil {
				return errors.New("cannot recover interrupted initialization")
			}
			continue
		}
		if err != nil {
			return err
		}
		if !m.Closed {
			now := time.Now().UTC()
			m.Closed = true
			m.Termination = "abrupt"
			m.RecoveredAt = &now
			// Recovery metadata must remain valid at the accepted warning-count
			// boundary. The lifecycle fields already convey abrupt recovery when
			// the optional explanatory warning cannot fit.
			hasRecoveryWarning := false
			for _, warning := range m.Warnings {
				if warning == "previous_execution_not_finalized" {
					hasRecoveryWarning = true
					break
				}
			}
			if !hasRecoveryWarning && len(m.Warnings) < maxWarnings {
				m.Warnings = append(m.Warnings, "previous_execution_not_finalized")
			}
			if m.Validate() != nil {
				return errors.New("recovered incident metadata fails schema validation")
			}
			if err := atomicJSON(path, "manifest.json", m); err != nil {
				return err
			}
		}
		if err := os.Remove(filepath.Join(path, "metadata.tmp")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot remove interrupted metadata write")
		}
	}
	return nil
}

func (s *Store) Start(version string, first model.Sample) (*Writer, error) {
	if s.active != nil {
		return nil, errors.New("an incident is already open")
	}
	quota := s.config.MaxBytes / int64(s.config.Retention)
	// A newly written incident must fit the offline reader, including when
	// a larger total disk budget was requested. MaxBytes remains an upper bound.
	if quota > MaxReadBytes {
		quota = MaxReadBytes
	}
	id := make([]byte, 6)
	if _, err := rand.Read(id); err != nil {
		return nil, errors.New("cannot allocate incident identifier")
	}
	caps := make([]string, 0, len(first.Metrics)+len(first.Pressure))
	for key := range first.Metrics {
		caps = append(caps, key)
	}
	for key := range first.Pressure {
		caps = append(caps, key)
	}
	sort.Strings(caps)
	m := Manifest{SchemaVersion: SchemaVersion, AgentVersion: version, StartedAt: first.Time.UTC(), Termination: "unknown", Target: target(first.Target), Config: s.config, Capabilities: caps, Warnings: []string{"sampling_can_miss_short_spikes", "buffered_disk_writes_may_be_lost_on_machine_failure", "cgroup_oom_does_not_identify_target_victim"}}
	if first.Target.CgroupID != "" {
		m.CgroupVersion = 2
	}
	// Validate deterministic inputs before retention removes any old evidence.
	if m.Validate() != nil {
		return nil, errors.New("initial incident metadata fails schema validation")
	}
	metadata, metaErr := json.MarshalIndent(m, "", "  ")
	line, lineErr := json.Marshal(record(first))
	if metaErr != nil || len(metadata)+1 > metadataLimit || lineErr != nil || len(line)+1 > maxSampleBytes || int64(len(line)+1) > (quota-metadataReserve)/2 || first.Time.IsZero() {
		return nil, errors.New("initial incident metadata or sample is invalid or exceeds its bound")
	}
	names, err := s.directories()
	if err != nil {
		return nil, err
	}
	for len(names) >= s.config.Retention {
		path := filepath.Join(s.root, names[0])
		if _, err := validateDirectory(path); err != nil {
			return nil, err
		}
		if err := os.RemoveAll(path); err != nil {
			return nil, errors.New("cannot apply incident retention")
		}
		names = names[1:]
	}
	var existing int64
	for _, name := range names {
		size, err := validateDirectory(filepath.Join(s.root, name))
		if err != nil {
			return nil, err
		}
		existing += size
	}
	if existing+quota > s.config.MaxBytes {
		return nil, errors.New("retained recordings do not fit new quota; use another output directory")
	}
	path := filepath.Join(s.root, "incident-"+first.Time.UTC().Format("20060102T150405.000000000Z")+"-"+hex.EncodeToString(id))
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, errors.New("cannot create incident")
	}
	if err := atomicJSON(path, "manifest.json", m); err != nil {
		return nil, err
	}
	if err := syncDirectory(s.root); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(path, "samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, errors.New("cannot create sample segment")
	}
	w := &Writer{store: s, Path: path, manifest: m, file: f, segmentLimit: (quota - metadataReserve) / 2}
	s.active = w
	return w, nil
}

func (w *Writer) Append(sample model.Sample, forceSync bool) error {
	if w.file == nil {
		return errors.New("incident is closed")
	}
	line, err := json.Marshal(record(sample))
	if err != nil {
		return errors.New("cannot encode sample")
	}
	line = append(line, '\n')
	if len(line) > maxSampleBytes || int64(len(line)) > w.segmentLimit {
		return errors.New("sample exceeds bounded segment capacity")
	}
	if w.size+int64(len(line)) > w.segmentLimit || w.segmentSamples >= MaxReadSamples/2 {
		if err := w.file.Sync(); err != nil {
			return errors.New("cannot sync sample segment")
		}
		if err := w.file.Close(); err != nil {
			return errors.New("cannot close sample segment")
		}
		w.file = nil
		previous := filepath.Join(w.Path, "samples.previous.jsonl")
		if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
			return errors.New("cannot retire sample segment")
		}
		if err := os.Rename(filepath.Join(w.Path, "samples.jsonl"), previous); err != nil {
			return errors.New("cannot rotate sample segment")
		}
		if err := syncDirectory(w.Path); err != nil {
			return err
		}
		w.file, err = os.OpenFile(filepath.Join(w.Path, "samples.jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("cannot open next sample segment")
		}
		w.size = 0
		w.segmentSamples = 0
		w.rotations++
	}
	n, err := w.file.Write(line)
	w.size += int64(n)
	if err != nil || n != len(line) {
		return errors.New("cannot append sample; recording stopped")
	}
	w.samples++
	w.segmentSamples++
	w.lastState = sample.State
	if forceSync {
		return w.Sync()
	}
	return nil
}

func (w *Writer) Sync() error {
	if w.file == nil {
		return errors.New("incident is closed")
	}
	if err := w.file.Sync(); err != nil {
		return errors.New("cannot sync samples")
	}
	return syncDirectory(w.Path)
}

func (w *Writer) Finish(termination string, end time.Time) error {
	if termination != "clean" && termination != "target-disappeared" && termination != "unknown" {
		return errors.New("invalid termination state")
	}
	if err := w.Sync(); err != nil {
		return err
	}
	if err := w.file.Close(); err != nil {
		return errors.New("cannot close samples")
	}
	w.file = nil
	if err := atomicJSON(w.Path, "summary.json", struct {
		SchemaVersion    int    `json:"schema_version"`
		SamplesWritten   uint64 `json:"samples_written"`
		SegmentRotations uint64 `json:"segment_rotations"`
		LastState        string `json:"last_state"`
	}{SchemaVersion, w.samples, w.rotations, w.lastState}); err != nil {
		return err
	}
	now := end.UTC()
	w.manifest.EndedAt = &now
	w.manifest.Termination = termination
	w.manifest.Closed = true
	if err := atomicJSON(w.Path, "manifest.json", w.manifest); err != nil {
		return err
	}
	w.store.active = nil
	return nil
}

// Close releases resources without claiming the recording ended cleanly. Call
// Finish first only after all intended samples have reached storage.
func (s *Store) Close() error {
	var errs []error
	if s.active != nil && s.active.file != nil {
		errs = append(errs, s.active.file.Close())
		s.active.file = nil
	}
	if s.lock != nil {
		errs = append(errs, s.lock.Close())
		s.lock = nil
	}
	return errors.Join(errs...)
}

func atomicJSON(dir, name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return errors.New("cannot encode incident metadata")
	}
	data = append(data, '\n')
	if len(data) > metadataLimit {
		return errors.New("incident metadata exceeds limit")
	}
	tmp := filepath.Join(dir, "metadata.tmp")
	if info, err := os.Lstat(tmp); err == nil && !info.Mode().IsRegular() {
		return errors.New("invalid metadata scratch file")
	}
	// Remove the directory entry, never truncate an existing inode: even a
	// regular file could be a hard link to unrelated data.
	if err := os.Remove(tmp); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.New("cannot retire metadata scratch file")
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("cannot create metadata scratch file")
	}
	writeErr := writeMetadata(f, data)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		if errors.Is(writeErr, io.ErrShortWrite) {
			return fmt.Errorf("cannot persist metadata: %w", io.ErrShortWrite)
		}
		return errors.New("cannot persist metadata")
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return errors.New("cannot replace metadata")
	}
	return syncDirectory(dir)
}

// writeMetadata checks the complete byte count even for a writer that fails to
// return an error on a short write. The caller must not rename partial metadata.
func writeMetadata(w io.Writer, data []byte) error {
	n, err := w.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func syncDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open incident directory for persistence")
	}
	defer f.Close()
	if err := f.Sync(); err != nil {
		return fmt.Errorf("cannot persist incident directory")
	}
	return nil
}
