package incident

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"time"

	"github.com/Savonitar/memflight/internal/schema"
)

const (
	// These schema-1 limits bound decoded maps, lists and strings independently
	// of the encoded-file budget. The reader checks them before retaining data.
	maxObjectFields  = 64
	maxWarnings      = 64
	maxStringBytes   = 256
	maxIdentityBytes = 128
	maxCapabilities  = 62 // 56 integer metrics and six PSI averages.
)

var errIntegrity = errors.New("incident input fails schema integrity validation")

// Validate checks manifest invariants without treating wall time as monotonic.
// A recovered abrupt recording has a recovery timestamp, not an invented end.
func (m Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion || !validTimestamp(m.StartedAt) || m.Config.Validate() != nil {
		return errIntegrity
	}
	if len(m.AgentVersion) == 0 || len(m.AgentVersion) > maxIdentityBytes || m.Target.PID <= 0 || !validTarget(m.Target) {
		return errIntegrity
	}
	if (m.CgroupVersion != 0 && m.CgroupVersion != 2) || (m.CgroupVersion == 0) != (m.Target.CgroupID == "") {
		return errIntegrity
	}
	if !m.Closed {
		if m.Termination != "unknown" || m.EndedAt != nil || m.RecoveredAt != nil {
			return errIntegrity
		}
	} else if m.Termination == "abrupt" {
		if m.EndedAt != nil || m.RecoveredAt == nil || !validTimestamp(*m.RecoveredAt) {
			return errIntegrity
		}
	} else {
		if m.Termination != "clean" && m.Termination != "target-disappeared" && m.Termination != "unknown" {
			return errIntegrity
		}
		if m.EndedAt == nil || !validTimestamp(*m.EndedAt) || m.RecoveredAt != nil {
			return errIntegrity
		}
	}
	if len(m.Capabilities) > maxCapabilities || !validStrings(m.Warnings, maxWarnings) {
		return errIntegrity
	}
	seen := map[string]bool{}
	for _, key := range m.Capabilities {
		if (!schema.IsMetric(key) && !schema.IsPressure(key)) || seen[key] {
			return errIntegrity
		}
		seen[key] = true
	}
	return nil
}

func validTimestamp(t time.Time) bool {
	_, offset := t.Zone()
	return !t.IsZero() && offset == 0
}

func validTarget(t Target) bool {
	return t.PID >= 0 && len(t.CgroupID) <= maxIdentityBytes && !strings.ContainsAny(t.CgroupID, "/\\\x00\r\n\t")
}

func validStrings(values []string, limit int) bool {
	if len(values) > limit {
		return false
	}
	for _, value := range values {
		if len(value) > maxStringBytes {
			return false
		}
	}
	return true
}

func (s sampleRecord) validate(m Manifest, previousElapsed int64, hasPrevious bool) error {
	if !validTimestamp(s.Time) || s.ElapsedNS < 0 || (hasPrevious && s.ElapsedNS <= previousElapsed) || !validTarget(s.Target) {
		return errIntegrity
	}
	if (s.Target.PID != 0 && m.Target.PID != 0 && s.Target.PID != m.Target.PID) ||
		(s.Target.StartTicks != 0 && m.Target.StartTicks != 0 && s.Target.StartTicks != m.Target.StartTicks) ||
		(s.Target.CgroupID != "" && m.Target.CgroupID != "" && s.Target.CgroupID != m.Target.CgroupID) {
		return errIntegrity
	}
	switch s.State {
	case "normal", "warning", "critical", "emergency", "recovered", "unknown":
	default:
		return errIntegrity
	}
	if len(s.Metrics) > 56 || len(s.Pressure) > 6 || len(s.Events) > 12 || !validStrings(s.Warnings, maxWarnings) || len(s.Unlimited) > 3 {
		return errIntegrity
	}
	for key := range s.Metrics {
		if !schema.IsMetric(key) {
			return errIntegrity
		}
	}
	for key, value := range s.Pressure {
		if !schema.IsPressure(key) || math.IsNaN(value) || math.IsInf(value, 0) || value < 0 || value > 100 {
			return errIntegrity
		}
	}
	for key, value := range s.Events {
		current, available := s.Metrics[key]
		if !schema.IsEvent(key) || !available || value == 0 || value > current {
			return errIntegrity
		}
	}
	seen := map[string]bool{}
	for _, key := range s.Unlimited {
		_, finite := s.Metrics[key]
		if !schema.IsUnlimited(key) || finite || seen[key] {
			return errIntegrity
		}
		seen[key] = true
	}
	return nil
}

// objectFields names the exact documented JSON spelling at every struct level.
// encoding/json accepts Unicode case aliases when decoding structs, so its own
// unknown-field check is not sufficient to enforce this schema boundary.
var objectFields = map[string]map[string]string{
	"manifest": {
		"schema_version": "number", "agent_version": "string", "started_at": "string",
		"ended_at": "nullable_string", "recovered_at": "nullable_string", "closed": "bool",
		"termination": "string", "target": "target", "cgroup_version": "number",
		"config": "config", "capabilities": "capabilities", "warnings": "warnings",
	},
	"sample": {
		"time": "string", "elapsed_ns": "number", "target": "target", "present": "nullable_bool",
		"metrics": "metrics", "pressure": "pressure", "unlimited": "unlimited",
		"warnings": "warnings", "state": "string", "events": "events",
	},
	"target": {"pid": "number", "start_ticks": "number", "cgroup_id": "string"},
	"config": {
		"interval_ns": "number", "elevated_interval_ns": "number", "sync_interval_ns": "number",
		"max_bytes_total": "number", "retention_including_active": "number", "thresholds": "thresholds",
	},
	"thresholds": {
		"warning_percent": "number", "critical_percent": "number",
		"emergency_percent": "number", "hysteresis_points": "number",
	},
}

// decodeBounded preflights exact field names, JSON types, duplicate keys and
// nesting/cardinality/string limits before unmarshalling. Errors never echo input.
func decodeBounded(data []byte, value any) error {
	var kind string
	switch value.(type) {
	case *Manifest:
		kind = "manifest"
	case *sampleRecord:
		kind = "sample"
	default:
		return errIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if scanValue(d, kind, 0) != nil {
		return errIntegrity
	}
	if _, err := d.Token(); err != io.EOF {
		return errIntegrity
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		return errIntegrity
	}
	return nil
}

func scanValue(d *json.Decoder, kind string, depth int) error {
	if depth > 8 {
		return errIntegrity
	}
	tok, err := d.Token()
	if err != nil {
		return errIntegrity
	}
	switch kind {
	case "number":
		if _, ok := tok.(json.Number); !ok {
			return errIntegrity
		}
		return nil
	case "nullable_string", "string":
		if tok == nil && kind == "nullable_string" {
			return nil
		}
		value, ok := tok.(string)
		if !ok || len(value) > maxStringBytes {
			return errIntegrity
		}
		return nil
	case "nullable_bool", "bool":
		if tok == nil && kind == "nullable_bool" {
			return nil
		}
		if _, ok := tok.(bool); !ok {
			return errIntegrity
		}
		return nil
	case "warnings", "capabilities", "unlimited":
		// Nil slices are emitted as null in manifest JSON; they are empty lists.
		if tok == nil {
			return nil
		}
		if tok != json.Delim('[') {
			return errIntegrity
		}
		limit := maxWarnings
		if kind == "unlimited" {
			limit = 3
		} else if kind == "capabilities" {
			limit = maxCapabilities
		}
		for count := 0; d.More(); count++ {
			if count >= limit || scanValue(d, "string", depth+1) != nil {
				return errIntegrity
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return errIntegrity
		}
		return nil
	case "metrics", "pressure", "events":
		// An unavailable metric scope can be represented by a nil map.
		if tok == nil {
			return nil
		}
	default:
		if _, known := objectFields[kind]; !known {
			return errIntegrity
		}
	}
	if tok != json.Delim('{') {
		return errIntegrity
	}
	seen := map[string]bool{}
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || len(key) > maxStringBytes || seen[key] || len(seen) >= maxObjectFields {
			return errIntegrity
		}
		seen[key] = true
		var childKind string
		switch kind {
		case "metrics":
			if !schema.IsMetric(key) || len(seen) > 56 {
				return errIntegrity
			}
			childKind = "number"
		case "pressure":
			if !schema.IsPressure(key) || len(seen) > 6 {
				return errIntegrity
			}
			childKind = "number"
		case "events":
			if !schema.IsEvent(key) || len(seen) > 12 {
				return errIntegrity
			}
			childKind = "number"
		default:
			var known bool
			childKind, known = objectFields[kind][key]
			if !known {
				return errIntegrity
			}
		}
		if scanValue(d, childKind, depth+1) != nil {
			return errIntegrity
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return errIntegrity
	}
	return nil
}
