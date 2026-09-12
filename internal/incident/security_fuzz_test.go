package incident

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Savonitar/memflight/internal/analyzer"
	"github.com/Savonitar/memflight/internal/model"
)

// Exercise the untrusted JSON boundary through semantic validation and reporting.
// Inputs are synthetic; the fuzz targets never open a recording or other file.
func FuzzSampleSecurityBoundary(f *testing.F) {
	seed, err := json.Marshal(record(sample(0)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"metric\u017f":{"cgroup.memory.current":null}}`))
	f.Add([]byte(`{"state":"invalid","\u017ftate":"normal"}`))
	f.Add([]byte(`{"target":{"pid":null},"metrics":{}}`))
	f.Add([]byte(`{"metrics":{"cgroup.memory.current":18446744073709551615}}`))
	f.Add([]byte(`{"warnings":["\u001b[31mSYNTHETIC_UNTRUSTED_TEXT"]}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxReadLineBytes {
			return
		}
		var s sampleRecord
		if decodeBounded(data, &s) != nil || s.validate(validationManifest(), 0, false) != nil {
			return
		}
		canonical, err := json.Marshal(s)
		if err != nil {
			t.Fatal("accepted sample cannot be encoded", err)
		}
		var again sampleRecord
		if decodeBounded(canonical, &again) != nil || again.validate(validationManifest(), 0, false) != nil {
			t.Fatal("accepted sample loses integrity on canonical round trip")
		}
		r := analyzer.Analyze([]model.Sample{s.model()}, "unknown")
		var text, structured bytes.Buffer
		if err := analyzer.FormatText(&text, r); err != nil {
			t.Fatal("valid sample cannot produce bounded text", err)
		}
		if err := analyzer.FormatJSON(&structured, r); err != nil || !json.Valid(structured.Bytes()) {
			t.Fatal("valid sample cannot produce bounded JSON", err)
		}
		if bytes.IndexByte(text.Bytes(), 0x1b) >= 0 {
			t.Fatal("untrusted input reached terminal control output")
		}
	})
}

func FuzzManifestSecurityBoundary(f *testing.F) {
	seed, err := json.Marshal(validationManifest())
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Add([]byte(`{"schema_version":99,"\u017fchema_version":1}`))
	f.Add([]byte(`{"config":{"thresholds":{"hysteresis_points":null}}}`))
	f.Add([]byte(`{"closed":null,"target":null}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > metadataLimit {
			return
		}
		var m Manifest
		if decodeBounded(data, &m) != nil || m.Validate() != nil {
			return
		}
		canonical, err := json.Marshal(m)
		if err != nil {
			t.Fatal("accepted manifest cannot be encoded", err)
		}
		var again Manifest
		if decodeBounded(canonical, &again) != nil || again.Validate() != nil {
			t.Fatal("accepted manifest loses integrity on canonical round trip")
		}
	})
}
