package incident

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePaddedSamples(t *testing.T, path string, count int, length func(int) int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := bufio.NewWriter(f)
	for i := 0; i < count; i++ {
		data, err := json.Marshal(record(sample(i)))
		if err != nil {
			t.Fatal(err)
		}
		size := len(data) + 1
		if length != nil {
			size = length(i)
		}
		if size < len(data)+1 {
			t.Fatal("invalid test padding")
		}
		if _, err := w.Write(data); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(bytes.Repeat([]byte{' '}, size-len(data)-1)); err != nil {
			t.Fatal(err)
		}
		if err := w.WriteByte('\n'); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadSampleCountBoundary(t *testing.T) {
	dir := writeValidationBundle(t, validationManifest())
	path := filepath.Join(dir, "samples.jsonl")
	writePaddedSamples(t, path, MaxReadSamples, nil)
	b, err := Read(dir)
	if err != nil || len(b.Samples) != MaxReadSamples {
		t.Fatalf("exact sample bound: count=%d err=%v", len(b.Samples), err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(record(sample(MaxReadSamples)))
	if _, err := f.Write(append(data, '\n')); err != nil {
		t.Fatal(err)
	}
	f.Close()
	requireInvalidBundle(t, dir)
}

func TestReadLineByteBoundary(t *testing.T) {
	for _, extra := range []int{0, 1} {
		dir := writeValidationBundle(t, validationManifest())
		writePaddedSamples(t, filepath.Join(dir, "samples.jsonl"), 1, func(int) int { return MaxReadLineBytes + extra })
		if extra == 0 {
			if _, err := Read(dir); err != nil {
				t.Fatalf("exact line bound: %v", err)
			}
		} else {
			requireInvalidBundle(t, dir)
		}
	}
	// The unfinished tail is recoverable only within the same line-size bound.
	for _, size := range []int{MaxReadLineBytes, MaxReadLineBytes + 1} {
		dir := writeValidationBundle(t, validationManifest(), record(sample(0)))
		f, err := os.OpenFile(filepath.Join(dir, "samples.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(bytes.Repeat([]byte{'x'}, size)); err != nil {
			t.Fatal(err)
		}
		f.Close()
		if size == MaxReadLineBytes {
			b, err := Read(dir)
			if err != nil || len(b.Samples) != 1 || !strings.Contains(strings.Join(b.Warnings, ","), "partial_final_line_ignored") {
				t.Fatal(b.Warnings, err)
			}
		} else {
			requireInvalidBundle(t, dir)
		}
	}
}

func TestReadTotalByteBoundaryIncludesManifest(t *testing.T) {
	dir := writeValidationBundle(t, validationManifest())
	manifest, err := os.Stat(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	// 1024 lines of 16 KiB minus the manifest bytes reaches the inclusive cap.
	path := filepath.Join(dir, "samples.jsonl")
	writePaddedSamples(t, path, MaxReadBytes/MaxReadLineBytes, func(i int) int {
		if i == 0 {
			return MaxReadLineBytes - int(manifest.Size())
		}
		return MaxReadLineBytes
	})
	if _, err := Read(dir); err != nil {
		t.Fatalf("exact total bound: %v", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	requireInvalidBundle(t, dir)
}

func TestReadRejectsSparseOversizeBeforeParsing(t *testing.T) {
	for _, split := range []bool{false, true} {
		dir := writeValidationBundle(t, validationManifest())
		names := []string{"samples.jsonl"}
		if split {
			names = append(names, "samples.previous.jsonl")
		}
		for _, name := range names {
			f, err := os.Create(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(MaxReadBytes / int64(len(names))); err != nil {
				t.Fatal(err)
			}
			f.Close()
		}
		b, err := Read(dir)
		if err == nil || !strings.Contains(err.Error(), "byte bound") || len(b.Samples) != 0 {
			t.Fatalf("sparse input not rejected by size: %v", err)
		}
	}
}

func TestReadRejectsChronologyAcrossSegments(t *testing.T) {
	for _, elapsed := range []int{1, 2} {
		dir := writeValidationBundle(t, validationManifest(), record(sample(elapsed)))
		data, _ := json.Marshal(record(sample(2)))
		if err := os.WriteFile(filepath.Join(dir, "samples.previous.jsonl"), append(data, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		requireInvalidBundle(t, dir)
	}
	// The first retained record may refer to a rotated-away earlier history.
	dir := writeValidationBundle(t, validationManifest(), record(sample(3)))
	data, _ := json.Marshal(record(sample(2)))
	if err := os.WriteFile(filepath.Join(dir, "samples.previous.jsonl"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if b, err := Read(dir); err != nil || len(b.Samples) != 2 {
		t.Fatal(err)
	}
}

func TestReadRejectsLargeManifestBeforeDecoding(t *testing.T) {
	dir := writeValidationBundle(t, validationManifest())
	f, err := os.Create(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(metadataLimit + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	requireInvalidBundle(t, dir)
}
