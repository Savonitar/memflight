package analyzer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	MaxSamples     = 4096
	MaxWindows     = 32
	MaxFindings    = 128
	MaxEvidence    = 8
	MaxWarnings    = 192
	MaxLimitations = 32
	MaxOutputBytes = 256 * 1024
)

var ErrReportTooLarge = errors.New("report exceeds bounded structure or output capacity")

// validateReport rejects oversized caller-constructed fields before formatting
// or JSON allocation. Generated reports contain only short fixed or numeric text.
func validateReport(r Report) error {
	if len(r.Findings) > MaxFindings || len(r.CollectionWarnings) > MaxWarnings || len(r.Limitations) > MaxLimitations {
		return ErrReportTooLarge
	}
	total := 0
	field := func(s string, limit int) bool {
		if len(s) > limit {
			return false
		}
		total += len(s)
		return total <= MaxOutputBytes
	}
	for _, f := range r.Findings {
		if len(f.Evidence) > MaxEvidence || !field(f.Code, 128) || !field(f.Pattern, 256) || !field(f.Confidence, 16) || !field(f.NextCheck, 512) {
			return ErrReportTooLarge
		}
		for _, evidence := range f.Evidence {
			if !field(evidence, 512) {
				return ErrReportTooLarge
			}
		}
	}
	for _, warning := range r.CollectionWarnings {
		if !field(warning.Code, 128) || !field(warning.Message, 512) {
			return ErrReportTooLarge
		}
	}
	for _, limitation := range r.Limitations {
		if !field(limitation, 512) {
			return ErrReportTooLarge
		}
	}
	return nil
}

type boundedWriter struct {
	w io.Writer
	n int
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	if len(p) > MaxOutputBytes-w.n {
		return 0, ErrReportTooLarge
	}
	n, err := w.w.Write(p)
	if n < 0 || n > len(p) {
		return 0, io.ErrShortWrite
	}
	w.n += n
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return n, err
}

// FormatJSON encodes into a buffer capped at 256 KiB before writing anything to
// the destination. Field preflight also bounds the JSON encoder's input size.
func FormatJSON(w io.Writer, report Report) error {
	if err := validateReport(report); err != nil {
		return err
	}
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&boundedWriter{w: &buffer})
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		return err
	}
	_, err := (&boundedWriter{w: w}).Write(buffer.Bytes())
	return err
}

// FormatText first counts the complete output without buffering it, so budget
// failures produce no partial report. The second pass streams checked writes.
func FormatText(w io.Writer, report Report) error {
	if err := validateReport(report); err != nil {
		return err
	}
	if err := writeText(&boundedWriter{w: io.Discard}, report); err != nil {
		return err
	}
	return writeText(&boundedWriter{w: w}, report)
}

func writeText(w io.Writer, report Report) error {
	write := func(format string, args ...any) error { _, err := fmt.Fprintf(w, format, args...); return err }
	if err := write("Memflight report (schema %d)\nSamples: %d\nAnalyzed samples: %d\nAnalysis windows: %d\nTruncated: %t\n", report.SchemaVersion, report.SampleCount, report.AnalyzedSampleCount, report.AnalysisWindows, report.Truncated); err != nil {
		return err
	}
	for _, finding := range report.Findings {
		if err := write("\nPattern: %s\nConfidence: %s\nEvidence:\n", finding.Pattern, finding.Confidence); err != nil {
			return err
		}
		for _, evidence := range finding.Evidence {
			if err := write("- %s\n", evidence); err != nil {
				return err
			}
		}
		if finding.NextCheck != "" {
			if err := write("Suggested next check: %s\n", finding.NextCheck); err != nil {
				return err
			}
		}
	}
	if len(report.CollectionWarnings) > 0 {
		if err := write("\nCollection warnings:\n"); err != nil {
			return err
		}
		for _, warning := range report.CollectionWarnings {
			if err := write("- %s (samples: %d; metadata: %t): %s\n", warning.Code, warning.SampleCount, warning.Metadata, warning.Message); err != nil {
				return err
			}
		}
	}
	if len(report.Limitations) > 0 {
		if err := write("\nLimitations:\n"); err != nil {
			return err
		}
		for _, limitation := range report.Limitations {
			if err := write("- %s\n", limitation); err != nil {
				return err
			}
		}
	}
	return nil
}
