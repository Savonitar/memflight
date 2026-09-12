// Package analyzer produces conservative, deterministic explanations of recorded
// numeric observations. It never diagnoses a runtime leak or an exit cause from
// memory growth alone.
package analyzer

import (
	"fmt"
	"math"
	"strings"

	"github.com/Savonitar/memflight/internal/model"
)

const mib uint64 = 1024 * 1024

// Report is the versioned machine-readable result. Confidence describes a
// heuristic's evidence strength; it is not a calibrated probability.
type Report struct {
	SchemaVersion       int                 `json:"schema_version"`
	SampleCount         int                 `json:"sample_count"`
	AnalyzedSampleCount int                 `json:"analyzed_sample_count"`
	AnalysisWindows     int                 `json:"analysis_windows"`
	Truncated           bool                `json:"truncated"`
	Findings            []Finding           `json:"findings"`
	CollectionWarnings  []CollectionWarning `json:"collection_warnings"`
	Limitations         []string            `json:"limitations"`
}

type Finding struct {
	Code       string   `json:"code"`
	Pattern    string   `json:"pattern"`
	Confidence string   `json:"confidence"`
	Evidence   []string `json:"evidence"`
	NextCheck  string   `json:"suggested_next_check,omitempty"`
}

// Analyze consumes samples in recorded order. Wall-clock changes do not affect
// durations. Identity changes and monotonic-clock resets break analysis windows.
// Only recognized warning codes are translated to fixed messages. Input and
// output budgets keep analysis bounded even when called without the bundle reader.
func Analyze(samples []model.Sample, termination string, manifestWarnings ...[]string) Report {
	r := Report{
		SchemaVersion:      1,
		SampleCount:        len(samples),
		Findings:           []Finding{},
		CollectionWarnings: []CollectionWarning{},
		Limitations: []string{
			"Sampling can miss short peaks and cannot identify individual allocations or request counts.",
			"Confidence is a deterministic evidence heuristic, not a calibrated probability.",
			"Unchanged or unavailable OOM counters do not rule out a kill after the final sample.",
		},
	}
	addLimit := func(s string) {
		for _, existing := range r.Limitations {
			if s == existing {
				return
			}
		}
		if len(r.Limitations) < MaxLimitations-1 {
			r.Limitations = append(r.Limitations, s)
		} else if len(r.Limitations) < MaxLimitations {
			r.Limitations = append(r.Limitations, "Additional limitations were omitted because the report limitation budget was reached.")
			r.Truncated = true
		}
	}
	if len(samples) > MaxSamples {
		samples = samples[:MaxSamples]
		r.Truncated = true
		addLimit("Input was limited to the first 4096 samples; later observations and their collection warnings were not analyzed.")
	}
	// Bound identity comparisons and list scans for direct callers. The input
	// objects remain untouched; numeric maps are queried only by fixed keys.
	bounded := make([]model.Sample, len(samples))
	copy(bounded, samples)
	for i := range bounded {
		if len(bounded[i].Target.CgroupID) > 128 {
			bounded[i].Target.CgroupID = ""
			addLimit("Oversized cgroup identity fields were excluded from attribution.")
		}
		if len(bounded[i].Unlimited) > MaxWarnings {
			bounded[i].Unlimited = bounded[i].Unlimited[:MaxWarnings]
			r.Truncated = true
			addLimit("Oversized unlimited-metric lists were truncated before analysis.")
		}
	}
	samples = bounded
	r.CollectionWarnings = collectWarnings(samples, manifestWarnings, &r.Truncated, addLimit)
	for start := 0; start < len(samples); {
		// Nine is the maximum generated findings in one window. Reserve one
		// slot for termination evidence, and stop before a whole-window batch.
		if r.AnalysisWindows == MaxWindows || len(r.Findings) > MaxFindings-1-9 {
			r.Truncated = true
			addLimit(fmt.Sprintf("Trend analysis stopped after %d samples in %d windows because its report budget was reached; remaining samples and identity windows were not analyzed for patterns.", r.AnalyzedSampleCount, r.AnalysisWindows))
			break
		}
		end := start + 1
		for end < len(samples) && samples[end].Target == samples[start].Target && samples[end].ElapsedNS > samples[end-1].ElapsedNS && samples[end-1].ElapsedNS >= 0 {
			end++
		}
		if end < len(samples) {
			if samples[end].Target != samples[start].Target {
				addLimit("Target identity changed; observations from different identities were analyzed separately.")
			} else {
				addLimit("Elapsed time was invalid or did not increase; observations across that boundary were analyzed separately.")
			}
		}
		window := samples[start:end]
		r.AnalysisWindows++
		r.AnalyzedSampleCount += len(window)
		procOK := window[0].Target.PID > 0 && window[0].Target.StartTicks > 0
		cgOK := window[0].Target.CgroupID != ""
		if !procOK {
			addLimit("Process identity was unavailable in some observations; process trends were suppressed for those observations.")
		}
		if !cgOK {
			addLimit("Cgroup identity was unavailable in some observations; cgroup trends and OOM attribution were suppressed for those observations.")
		}
		if window[0].ElapsedNS < 0 {
			addLimit("Elapsed time was invalid or did not increase; observations across that boundary were analyzed separately.")
			start = end
			continue
		}
		before := len(r.Findings)
		analyzeWindow(&r, window, procOK, cgOK, addLimit)
		if start != 0 || end != len(samples) {
			for i := before; i < len(r.Findings); i++ {
				r.Findings[i].Evidence = append(r.Findings[i].Evidence, fmt.Sprintf("Evidence window: recorded samples %d through %d.", start+1, end))
			}
		}
		start = end
	}
	if termination == "abrupt" || termination == "unknown" || termination == "target-disappeared" {
		evidence := "The recording's termination state is unknown."
		if termination == "abrupt" {
			evidence = "A previous recording was left open and marked abrupt."
		} else if termination == "target-disappeared" {
			evidence = "The recorder observed that the target disappeared."
		}
		r.Findings = append(r.Findings, Finding{
			Code: "exit_cause_unresolved", Pattern: "Exit cause unresolved", Confidence: "low",
			Evidence:  []string{evidence, "A recording ending or a target disappearing does not establish its exit cause, even if a cgroup OOM counter also increased."},
			NextCheck: "Correlate the target's exit status with kernel or provider evidence.",
		})
	}
	if len(r.Findings) == 0 {
		r.Findings = append(r.Findings, Finding{
			Code: "insufficient_evidence", Pattern: "Insufficient evidence for a supported pattern", Confidence: "low",
			Evidence:  []string{fmt.Sprintf("Analyzed %d of %d recorded samples; no supported pattern met the conservative evidence thresholds within that coverage.", r.AnalyzedSampleCount, r.SampleCount)},
			NextCheck: "Collect a longer recording with stable target identity and available numeric metrics.",
		})
	}
	return r
}

func analyzeWindow(r *Report, samples []model.Sample, procOK, cgOK bool, addLimit func(string)) {
	if len(samples) < 2 {
		addLimit("Some observation windows contain fewer than two samples; changes cannot be established within those windows.")
		return
	}
	growthSamples := samples
	for i, sample := range samples {
		if sample.Present != nil && !*sample.Present {
			growthSamples = samples[:i]
			addLimit("Memory and process growth trends use only samples before the first observation marking the target absent; cgroup OOM-counter and utilization evidence can continue after disappearance. Memory released at target exit is not classified as workload recovery.")
			break
		}
	}
	sourceFor := func(key string) []model.Sample {
		if strings.HasPrefix(key, "proc.") || key == "cgroup.memory.stat.anon" || key == "cgroup.memory.stat.file" || key == "cgroup.memory.swap.current" {
			return growthSamples
		}
		return samples
	}
	durationFor := func(key string) float64 {
		source := sourceFor(key)
		if len(source) < 2 {
			return 0
		}
		return float64(source[len(source)-1].ElapsedNS-source[0].ElapsedNS) / 1e9
	}
	denseFor := func(key string) bool {
		source := sourceFor(key)
		for i := 1; i < len(source); i++ {
			if source[i].ElapsedNS-source[i-1].ElapsedNS > 10_000_000_000 {
				addLimit("Some adjacent samples are more than 10 seconds apart; gradual anonymous growth was not classified across those gaps.")
				return false
			}
		}
		return true
	}
	series := func(key string) ([]uint64, bool) {
		source := sourceFor(key)
		if len(source) < 2 {
			return nil, false
		}
		values := make([]uint64, len(source))
		for i, sample := range source {
			v, ok := sample.Metrics[key]
			if !ok {
				addLimit("Some metrics were unavailable; missing values were not treated as zero and incomplete series were excluded from trend analysis.")
				return nil, false
			}
			values[i] = v
		}
		return values, true
	}
	add := func(code, pattern, confidence, check string, evidence ...string) {
		if len(r.Findings) >= MaxFindings-1 {
			r.Truncated = true
			addLimit("Additional pattern findings were omitted because the finding budget was reached.")
			return
		}
		if len(evidence) >= MaxEvidence {
			evidence = evidence[:MaxEvidence-1]
			r.Truncated = true
			addLimit("Some finding evidence was omitted because the evidence budget was reached.")
		}
		r.Findings = append(r.Findings, Finding{Code: code, Pattern: pattern, Confidence: confidence, Evidence: evidence, NextCheck: check})
	}
	if cgOK {
		for _, key := range []string{"cgroup.memory.events.local.oom_kill", "cgroup.memory.events.oom_kill"} {
			var increases uint64
			var changes int
			for i := 1; i < len(samples); i++ {
				previous, previousOK := samples[i-1].Metrics[key]
				current, currentOK := samples[i].Metrics[key]
				if !previousOK || !currentOK {
					continue
				}
				if current < previous {
					addLimit("An OOM counter decreased; resets were excluded from OOM counts, and its continuity is uncertain.")
					continue
				}
				if current > previous {
					// Saturation keeps even malicious/corrupt inputs from wrapping.
					delta := current - previous
					if delta > math.MaxUint64-increases {
						increases = math.MaxUint64
					} else {
						increases += delta
					}
					changes++
				}
			}
			if changes > 0 {
				add("observed_oom_counter_increase", "Observed OOM-kill counter increase", "high",
					"Correlate the target's exit status with kernel or provider evidence to establish the victim and the applicable memory limit.",
					fmt.Sprintf("%s increased by %d across %d adjacent sample pairs.", key, increases, changes),
					"This records OOM victims in the counter's scope, not proof that the target was killed or that this cgroup's memory.max caused the kill.")
				if key == "cgroup.memory.events.oom_kill" {
					addLimit("memory.events is hierarchical and can include OOM victims in descendant cgroups.")
				}
				// Local and hierarchical counters overlap. Report local if available
				// and increasing; never add the two counts together.
				break
			}
		}
	}
	anonKey := ""
	var anon []uint64
	if cgOK {
		if values, ok := series("cgroup.memory.stat.anon"); ok {
			anonKey, anon = "cgroup.memory.stat.anon", values
		}
	}
	if anonKey == "" && procOK {
		if values, ok := series("proc.status.RssAnon"); ok {
			anonKey, anon = "proc.status.RssAnon", values
		}
	}
	if len(anon) >= 4 && durationFor(anonKey) >= 10 && denseFor(anonKey) && gradual(anon, 8*mib) {
		evidence := []string{changeEvidence(anonKey, anon, durationFor(anonKey), true), "At least three sampled increases occurred; no single increase accounts for most of the net growth."}
		if anonKey == "cgroup.memory.stat.anon" && procOK {
			if values, ok := series("proc.status.RssAnon"); ok && materialGrowth(values, 8*mib, 0.20) {
				evidence = append(evidence, changeEvidence("proc.status.RssAnon", values, durationFor("proc.status.RssAnon"), true))
			}
		}
		add("gradual_anonymous_growth", "Probable gradual anonymous-memory growth", "medium", "Compare runtime heap metrics with process anonymous RSS in a controlled reproduction; anonymous memory alone cannot identify a leak or allocator.", evidence...)
	}
	if cgOK {
		if current, ok := series("cgroup.memory.current"); ok {
			var highestRatio float64
			var limitAtHigh, currentAtHigh uint64
			for i, value := range current {
				limit, exists := samples[i].Metrics["cgroup.memory.max"]
				if !exists || limit == 0 {
					continue
				}
				unlimited := false
				for _, key := range samples[i].Unlimited {
					if len(key) <= 128 && key == "cgroup.memory.max" {
						unlimited = true
					}
				}
				if unlimited {
					addLimit("A cgroup limit was recorded as both finite and unlimited; contradictory limit observations were excluded from utilization analysis.")
					continue
				}
				ratio := float64(value) / float64(limit)
				if ratio > highestRatio {
					highestRatio, limitAtHigh, currentAtHigh = ratio, limit, value
				}
			}
			if highestRatio >= 0.90 {
				add("high_cgroup_memory_usage", "Observed high cgroup memory usage", "high",
					"Check the effective ancestor and VM limits as well as this cgroup's memory.max.",
					fmt.Sprintf("A sample recorded cgroup.memory.current at %s against cgroup.memory.max of %s (%.1f%%).", formatBytes(currentAtHigh), formatBytes(limitAtHigh), highestRatio*100),
					"The ratio uses physical cgroup memory only; swap is excluded from the denominator.")
			}
			// Growth and recovery describe the observed workload while present.
			// Its exit can itself free memory, so keep the final cgroup-only
			// observation for pressure/OOM evidence without treating it as recovery.
			current = current[:len(growthSamples)]
			if len(current) >= 2 {
				largest, index := largestIncrease(current)
				if index > 0 && largest >= 16*mib && float64(largest) >= float64(current[index-1])*0.25 {
					seconds := float64(samples[index].ElapsedNS-samples[index-1].ElapsedNS) / 1e9
					// A long recording gap cannot establish a sampled spike. This
					// heuristic describes an observed jump, never a one-request cause.
					if seconds <= 10 && float64(largest) >= positiveGrowth(current)*0.75 {
						add("sampled_memory_jump", "Observed sampled memory jump", "medium",
							"Repeat with a shorter sampling interval and runtime allocation metrics to distinguish one allocation from accumulated work.",
							fmt.Sprintf("cgroup.memory.current rose from %s to %s between adjacent samples %.3f seconds apart.", formatBytes(current[index-1]), formatBytes(current[index]), seconds),
							"The largest sampled increase accounts for at least 75% of sampled positive changes; the peak between samples is unknown.")
					}
				}
				peak, peakIndex := current[0], 0
				for i, v := range current {
					if v > peak {
						peak, peakIndex = v, i
					}
				}
				last := current[len(current)-1]
				if peakIndex < len(current)-1 && peak > last && peak-last >= 8*mib && float64(peak-last) >= float64(peak)*0.20 {
					seconds := float64(growthSamples[len(growthSamples)-1].ElapsedNS-growthSamples[peakIndex].ElapsedNS) / 1e9
					add("observed_memory_recovery", "Observed memory recovery", "high",
						"Correlate the decrease with workload activity; this recorder has no signal establishing application idleness.",
						fmt.Sprintf("cgroup.memory.current fell from a sampled high of %s to %s over %.3f seconds.", formatBytes(peak), formatBytes(last), seconds))
				}
			}
		}
		if file, ok := series("cgroup.memory.stat.file"); ok && len(file) >= 3 && materialGrowth(file, 8*mib, 0.20) {
			add("file_memory_growth", "Observed file-memory growth", "medium", "Inspect file-cache and shared-memory activity; the cgroup file metric includes tmpfs and shared memory as well as cache.", changeEvidence("cgroup.memory.stat.file", file, durationFor("cgroup.memory.stat.file"), true))
		}
		if swap, ok := series("cgroup.memory.swap.current"); ok && materialGrowth(swap, 4*mib, 0.20) {
			add("swap_usage_growth", "Observed swap usage growth", "high", "Correlate swap usage with PSI and swap I/O; usage alone does not establish active thrashing.", changeEvidence("cgroup.memory.swap.current", swap, durationFor("cgroup.memory.swap.current"), true))
		}
	}
	if procOK {
		for _, metric := range []struct {
			key, code, pattern, check string
			minimum                   uint64
		}{
			{"proc.status.Threads", "thread_count_growth", "Observed thread-count growth", "Inspect runtime thread-pool behavior during the same workload.", 4},
			{"proc.fd_count", "file_descriptor_growth", "Observed file-descriptor count growth", "Check whether the workload intentionally retains descriptors and whether counts recover after work completes.", 16},
		} {
			if values, ok := series(metric.key); ok && len(values) >= 3 && materialGrowth(values, metric.minimum, 0.25) {
				add(metric.code, metric.pattern, "high", metric.check, changeEvidence(metric.key, values, durationFor(metric.key), false))
			}
		}
	}
}

func materialGrowth(values []uint64, minimum uint64, relative float64) bool {
	first, last := values[0], values[len(values)-1]
	return last > first && last-first >= minimum && float64(last-first) >= float64(first)*relative
}

func gradual(values []uint64, minimum uint64) bool {
	if !materialGrowth(values, minimum, 0.20) {
		return false
	}
	var increases, decreases int
	for i := 1; i < len(values); i++ {
		if values[i] > values[i-1] {
			increases++
		} else if values[i] < values[i-1] {
			decreases++
		}
	}
	largest, _ := largestIncrease(values)
	net := values[len(values)-1] - values[0]
	return increases >= 3 && decreases <= (len(values)-1)/5 && float64(largest) <= float64(net)*0.60
}

func largestIncrease(values []uint64) (uint64, int) {
	var largest uint64
	var index int
	for i := 1; i < len(values); i++ {
		if values[i] > values[i-1] && values[i]-values[i-1] > largest {
			largest, index = values[i]-values[i-1], i
		}
	}
	return largest, index
}

func positiveGrowth(values []uint64) float64 {
	var total float64
	for i := 1; i < len(values); i++ {
		if values[i] > values[i-1] {
			total += float64(values[i] - values[i-1])
		}
	}
	return total
}

func changeEvidence(key string, values []uint64, seconds float64, memory bool) string {
	first, last := values[0], values[len(values)-1]
	if memory {
		return fmt.Sprintf("%s rose from %s to %s (increase %s) over %.3f seconds.", key, formatBytes(first), formatBytes(last), formatBytes(last-first), seconds)
	}
	return fmt.Sprintf("%s rose from %d to %d (increase %d) over %.3f seconds.", key, first, last, last-first, seconds)
}

func formatBytes(value uint64) string {
	return fmt.Sprintf("%d bytes (%.2f MiB)", value, float64(value)/float64(mib))
}
