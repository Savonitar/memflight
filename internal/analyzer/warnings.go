package analyzer

import (
	"sort"
	"strings"

	"github.com/Savonitar/memflight/internal/model"
	"github.com/Savonitar/memflight/internal/schema"
)

// CollectionWarning translates an exact recognized code into a fixed message.
// SampleCount counts distinct retained samples carrying this warning. Metadata
// means it also occurred in a manifest or reader warning list.
type CollectionWarning struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	SampleCount int    `json:"sample_count"`
	Metadata    bool   `json:"metadata"`
}

var warningMessages = buildWarningMessages()

func buildWarningMessages() map[string]string {
	messages := map[string]string{
		"target_exited_state":                                 "The target was observed in an exited or zombie state; process collection stopped for that observation.",
		"target_missing":                                      "The configured target was absent during collection.",
		"target_changed_during_collection":                    "Target identity changed during a sample; inconsistent observations were discarded.",
		"target_cgroup_changed_during_collection":             "The target cgroup changed during a sample; inconsistent cgroup observations were discarded.",
		"cached_cgroup_identity_unavailable_or_changed":       "The last verified cgroup could not be safely identified after target disappearance; final cgroup evidence may be unavailable.",
		"cgroup_identity_path_only":                           "Cgroup identity used a path identifier without a verified filesystem identity; recreation detection is limited.",
		"cgroup_mount_mapping_unverified":                     "The cgroup mount mapping could not be verified; cgroup collection was unavailable.",
		"cgroup_mount_mapping_ambiguous":                      "The cgroup mount mapping was ambiguous; cgroup metrics were omitted to avoid incorrect attribution.",
		"target_cgroup_outside_visible_mount":                 "The target cgroup was outside the visible mount; cgroup metrics were omitted.",
		"cgroup_ancestor_limits_may_be_hidden":                "Cgroup namespaces may hide ancestor limits; the visible leaf limit may differ from the effective memory constraint.",
		"cgroup_ancestor_limits_not_evaluated":                "Ancestor cgroup limits were not evaluated; leaf memory utilization does not establish effective headroom.",
		"cgroup_memory_limit_unlimited":                       "The visible cgroup memory.max is unlimited; physical utilization cannot be calculated from that leaf limit.",
		"sampling_can_miss_short_spikes":                      "Sampling can miss peaks shorter than the sampling interval.",
		"buffered_disk_writes_may_be_lost_on_machine_failure": "Buffered sample writes may be lost if the machine fails before persistence completes.",
		"cgroup_oom_does_not_identify_target_victim":          "A cgroup OOM counter does not identify the target as the victim or establish which memory limit caused the kill.",
		"previous_execution_not_finalized":                    "A previous recording was not finalized and was recovered as abrupt; this alone does not prove OOM.",
		"partial_final_line_ignored":                          "An incomplete final sample line was ignored; the tail of the incident may be missing.",
		"recording_not_finalized":                             "The recording is still open or was not finalized; its termination has not been established.",
		"history_before_first_retained_sample_unavailable":    "History before the first retained sample is unavailable; rotation or a collection gap may have removed the beginning.",
		"no_sample_segment":                                   "No sample segment survived; only incident metadata is available.",
	}
	// Scopes are exact collector-owned values. Do not recognize arbitrary
	// prefixes or render any suffix supplied by an incident.
	readScopes := map[string]string{
		"target_identity":            "Target process identity",
		"target_cgroup":              "Target cgroup membership",
		"cgroup_directory":           "Target cgroup directory identity",
		"cgroup_mountinfo":           "Cgroup mount mapping",
		"cgroup_memory_stat":         "Cgroup memory.stat",
		"cgroup_memory_events":       "Hierarchical cgroup memory.events",
		"cgroup_memory_events_local": "Local cgroup memory.events",
		"cgroup_memory_pressure":     "Cgroup memory pressure",
		"proc_status":                "Target process status metrics",
		"proc_smaps_rollup":          "Target process smaps_rollup metrics",
		"proc_fd_count":              "Target file-descriptor count",
	}
	for _, key := range []string{
		"cgroup.memory.current", "cgroup.memory.peak", "cgroup.memory.min",
		"cgroup.memory.low", "cgroup.memory.high", "cgroup.memory.max",
		"cgroup.memory.swap.current", "cgroup.memory.swap.peak", "cgroup.memory.swap.max",
	} {
		if schema.IsMetric(key) {
			readScopes[strings.ReplaceAll(key, ".", "_")] = key
		}
	}
	for scope, label := range readScopes {
		for suffix, detail := range map[string]string{
			"_permission_denied":     " could not be read because permission was denied.",
			"_unavailable":           " was unavailable on this system or during this observation.",
			"_too_large":             " exceeded the collector's bounded read limit and was excluded.",
			"_invalid_or_unreadable": " was invalid or unreadable; the affected capability was unavailable.",
		} {
			messages[scope+suffix] = label + detail
		}
	}
	for _, scope := range []string{
		"cgroup_memory_current", "cgroup_memory_peak", "cgroup_memory_min", "cgroup_memory_low",
		"cgroup_memory_high", "cgroup_memory_max", "cgroup_memory_swap_current", "cgroup_memory_swap_peak",
		"cgroup_memory_swap_max", "cgroup_memory_stat", "cgroup_memory_events", "cgroup_memory_events_local",
		"cgroup_memory_pressure", "proc_status", "proc_smaps",
	} {
		label := readScopes[scope]
		if scope == "proc_smaps" {
			label = "Target process smaps_rollup metrics"
		}
		messages[scope+"_invalid"] = label + " contained malformed numeric fields; affected values were excluded."
	}
	for _, key := range schema.MetricKeys() {
		if schema.IsEvent(key) {
			messages["counter_reset:"+key] = key + " decreased; the counter baseline reset instead of producing a wrapped delta."
		}
	}
	return messages
}

func collectWarnings(samples []model.Sample, metadata [][]string, truncated *bool, addLimit func(string)) []CollectionWarning {
	counts := make(map[string]CollectionWarning)
	unknown, limited := false, false
	consume := func(codes []string, fromMetadata bool) {
		if len(codes) > MaxWarnings {
			codes = codes[:MaxWarnings]
			limited = true
		}
		seen := make(map[string]bool, len(codes))
		for _, code := range codes {
			if len(code) > 128 {
				unknown = true
				continue
			}
			message, recognized := warningMessages[code]
			if !recognized {
				unknown = true
				continue
			}
			if seen[code] {
				continue
			}
			seen[code] = true
			value, exists := counts[code]
			if !exists {
				if len(counts) == MaxWarnings {
					limited = true
					continue
				}
				value = CollectionWarning{Code: code, Message: message}
			}
			if fromMetadata {
				value.Metadata = true
			} else {
				value.SampleCount++
			}
			counts[code] = value
		}
	}
	for _, sample := range samples {
		consume(sample.Warnings, false)
	}
	if len(metadata) > MaxWindows {
		metadata = metadata[:MaxWindows]
		limited = true
	}
	for _, codes := range metadata {
		consume(codes, true)
	}
	if unknown {
		addLimit("Unrecognized collection warning codes were omitted; their input text was not included in the report.")
	}
	if limited {
		*truncated = true
		addLimit("Collection warning input or output exceeded its budget; some warning codes or occurrences were not included.")
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]CollectionWarning, 0, len(keys))
	for _, key := range keys {
		result = append(result, counts[key])
	}
	return result
}
