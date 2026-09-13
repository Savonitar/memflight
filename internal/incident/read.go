package incident

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/Savonitar/memflight/internal/model"
)

const (
	// Report limits are smaller than the recorder's configurable disk maximum.
	// They bound encoded input and decoded cardinality, not an exact RSS ceiling.
	// Read rejects larger histories rather than presenting a truncated prefix.
	MaxReadBytes     = 16 * 1024 * 1024 // manifest plus both sample segments
	MaxReadSamples   = 4096
	MaxReadLineBytes = 16 * 1024 // includes the terminating newline
)

type Bundle struct {
	Manifest Manifest
	Samples  []model.Sample
	Warnings []string
}

func openRegular(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("incident input must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		f.Close()
		return nil, errors.New("incident input changed while opening")
	}
	return f, nil
}

func readManifest(dir string) (Manifest, error) {
	m, _, err := readManifestSized(dir)
	return m, err
}

func readManifestSized(dir string) (Manifest, int64, error) {
	var m Manifest
	f, err := openRegular(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return m, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > metadataLimit {
		return m, 0, errors.New("cannot read bounded manifest")
	}
	data, err := io.ReadAll(io.LimitReader(f, metadataLimit+1))
	if err != nil || len(data) > metadataLimit || int64(len(data)) != info.Size() {
		return m, 0, errors.New("cannot read bounded manifest")
	}
	if decodeBounded(data, &m) != nil || m.Validate() != nil {
		return Manifest{}, 0, errIntegrity
	}
	return m, int64(len(data)), nil
}

// Read validates a bounded schema-1 incident before exposing any report input.
// A partial last line in either segment is ignored with a warning; malformed
// complete lines, inconsistent semantics, changed files and exceeded bounds are
// errors returning an empty Bundle. Offline reading never modifies recordings.
func Read(dir string) (Bundle, error) {
	var b Bundle
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return Bundle{}, errors.New("incident must be a real directory")
	}
	var total int64
	b.Manifest, total, err = readManifestSized(dir)
	if err != nil {
		return Bundle{}, errors.New("cannot read a valid supported incident manifest")
	}
	type segment struct {
		file *os.File
		size int64
	}
	var segments []segment
	defer func() {
		for _, segment := range segments {
			segment.file.Close()
		}
	}()
	// Inspect both sizes before decoding samples, including sparse-file sizes.
	for _, name := range []string{"samples.previous.jsonl", "samples.jsonl"} {
		f, err := openRegular(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return Bundle{}, errors.New("cannot open sample segment")
		}
		fi, err := f.Stat()
		if err != nil {
			f.Close()
			return Bundle{}, errors.New("cannot inspect sample segment")
		}
		segments = append(segments, segment{f, fi.Size()})
		if fi.Size() < 0 || fi.Size() > MaxReadBytes-total {
			return Bundle{}, errors.New("incident exceeds offline input byte bound")
		}
		total += fi.Size()
	}
	for _, segment := range segments {
		if err := readSegment(segment.file, segment.size, &b); err != nil {
			return Bundle{}, err
		}
	}
	if len(segments) == 0 {
		b.Warnings = append(b.Warnings, "no_sample_segment")
	}
	if !b.Manifest.Closed {
		b.Warnings = append(b.Warnings, "recording_not_finalized")
	}
	if len(b.Samples) > 0 && b.Samples[0].ElapsedNS > 0 {
		b.Warnings = append(b.Warnings, "history_before_first_retained_sample_unavailable")
	}
	return b, nil
}

func readSegment(f *os.File, size int64, b *Bundle) error {
	r := bufio.NewReaderSize(io.LimitReader(f, size+1), MaxReadLineBytes+1)
	var consumed int64
	for {
		line, readErr := r.ReadSlice('\n')
		consumed += int64(len(line))
		if consumed > size {
			return errors.New("sample segment changed while reading")
		}
		if readErr == bufio.ErrBufferFull || len(line) > MaxReadLineBytes {
			return errors.New("sample line exceeds offline size bound")
		}
		if readErr == io.EOF {
			if consumed != size {
				return errors.New("sample segment changed while reading")
			}
			if len(line) > 0 {
				b.Warnings = append(b.Warnings, "partial_final_line_ignored")
			}
			break
		}
		if readErr != nil {
			return errors.New("cannot read sample segment")
		}
		if len(bytes.TrimSpace(line)) == 0 {
			return errors.New("empty sample line")
		}
		if len(b.Samples) >= MaxReadSamples {
			return errors.New("incident exceeds offline sample count bound")
		}
		var record sampleRecord
		previousElapsed := int64(0)
		if len(b.Samples) > 0 {
			previousElapsed = b.Samples[len(b.Samples)-1].ElapsedNS
		}
		if decodeBounded(line, &record) != nil || record.validate(b.Manifest, previousElapsed, len(b.Samples) > 0) != nil {
			return errIntegrity
		}
		b.Samples = append(b.Samples, record.model())
	}
	if info, err := f.Stat(); err != nil || info.Size() != size {
		return errors.New("sample segment changed while reading")
	}
	return nil
}
