package cli

import (
	"slices"
	"testing"
	"time"
)

func Test_repeatLogger(t *testing.T) {
	var repeats repeatLogger
	for _, step := range []struct {
		name        string
		key         string
		value       string
		wantChanged bool
		wantRepeats uint64
	}{
		{"the first value of a key is a change", "pf anchor", "intact", true, 0},
		{"the same value repeats", "pf anchor", "intact", false, 1},
		{"the same value repeats again", "pf anchor", "intact", false, 2},
		{"a new value reports the run before it", "pf anchor", "missing", true, 2},
		{"the new value repeats", "pf anchor", "missing", false, 1},
		{"the value before is a change again", "pf anchor", "intact", true, 1},
		{"a second key starts on its own", "tunnels", "utun0", true, 0},
		{"the second key repeats", "tunnels", "utun0", false, 1},
		{"the first key keeps its own count", "pf anchor", "intact", false, 1},
	} {
		t.Run(step.name, func(t *testing.T) {
			changed, count := repeats.changed(step.key, step.value)
			if changed != step.wantChanged || count != step.wantRepeats {
				t.Errorf("changed(%q, %q) = %v, %d, want %v, %d",
					step.key, step.value, changed, count, step.wantChanged, step.wantRepeats)
			}
		})
	}
}

func Test_wakeReporter(t *testing.T) {
	base := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	var wake wakeReporter
	var armed []func()
	wake.after = func(_ time.Duration, fn func()) { armed = append(armed, fn) }
	var emitted []wakeReport
	emit := func(report wakeReport) { emitted = append(emitted, report) }
	fireHeld := func() {
		for _, fn := range armed {
			fn()
		}
		armed = nil
	}

	// netmon reports first and knows no gap, so its report waits.
	wake.note(base, wakeReport{source: "netmon"}, emit)
	if len(emitted) != 0 || len(armed) != 1 {
		t.Fatalf("a report without a gap must wait: emitted %d, timers %d", len(emitted), len(armed))
	}
	// The detector reports inside the hold with the gap, so it replaces the
	// held report.
	wake.note(base.Add(2*time.Second), wakeReport{source: "detector", gap: 90 * time.Second}, emit)
	fireHeld()
	if len(emitted) != 1 || emitted[0].source != "detector" {
		t.Fatalf("emitted %+v, want the detector report alone", emitted)
	}
	// Every other report of this wake is the same wake.
	wake.note(base.Add(10*time.Second), wakeReport{source: "netmon"}, emit)
	wake.note(base.Add(12*time.Second), wakeReport{source: "detector", gap: 91 * time.Second}, emit)
	if len(emitted) != 1 {
		t.Fatalf("emitted %d reports inside the window, want 1", len(emitted))
	}

	// A wake that only netmon sees reports without a gap when the hold ends.
	wake.note(base.Add(40*time.Second), wakeReport{source: "netmon"}, emit)
	if len(emitted) != 1 || len(armed) != 1 {
		t.Fatalf("a new wake must arm one hold: emitted %d, timers %d", len(emitted), len(armed))
	}
	fireHeld()
	if len(emitted) != 2 || emitted[1].source != "netmon" || emitted[1].gap != 0 {
		t.Fatalf("emitted %+v, want the netmon report after the hold", emitted)
	}
	// A gap that arrives after the hold is too late: one event per wake.
	wake.note(base.Add(50*time.Second), wakeReport{source: "detector", gap: 92 * time.Second}, emit)
	if len(emitted) != 2 {
		t.Fatalf("emitted %d reports, want no second report of one wake", len(emitted))
	}

	// The detector first reports at once, and netmon adds nothing.
	wake.note(base.Add(80*time.Second), wakeReport{source: "detector", gap: 93 * time.Second}, emit)
	wake.note(base.Add(82*time.Second), wakeReport{source: "netmon"}, emit)
	fireHeld()
	if len(emitted) != 3 || emitted[2].source != "detector" || len(armed) != 0 {
		t.Fatalf("emitted %+v with %d timers, want one detector report and no hold", emitted, len(armed))
	}
}

func Test_noiseCoalescer(t *testing.T) {
	base := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)

	t.Run("a storm reports once every ten minutes", func(t *testing.T) {
		const deltas = 100
		const cadence = 15 * time.Second
		var noise noiseCoalescer
		var got []noiseSummary
		for i := 0; i < deltas; i++ {
			interfaces := []string{"awdl0"}
			if i%2 == 1 {
				interfaces = []string{"llw0", "awdl0"}
			}
			summary, emit := noise.add(interfaces, base.Add(time.Duration(i)*cadence))
			if !emit {
				continue
			}
			got = append(got, summary)
		}
		want := []noiseSummary{{
			Count:      1,
			First:      base,
			Last:       base,
			Interfaces: []string{"awdl0"},
		}, {
			Count:      40,
			First:      base.Add(cadence),
			Last:       base.Add(10 * time.Minute),
			Interfaces: []string{"awdl0", "llw0"},
		}, {
			Count:      40,
			First:      base.Add(10*time.Minute + cadence),
			Last:       base.Add(20 * time.Minute),
			Interfaces: []string{"awdl0", "llw0"},
		}}
		assertSummaries(t, got, want)
	})

	t.Run("a flush reports the open window", func(t *testing.T) {
		var noise noiseCoalescer
		if _, emit := noise.flush(base); emit {
			t.Fatal("an empty coalescer reported a summary")
		}
		for _, offset := range []time.Duration{0, time.Minute, 2 * time.Minute} {
			noise.add([]string{"awdl0"}, base.Add(offset))
		}
		summary, emit := noise.flush(base.Add(3 * time.Minute))
		if !emit {
			t.Fatal("the flush reported no summary for an open window")
		}
		assertSummaries(t, []noiseSummary{summary}, []noiseSummary{{
			Count:      2,
			First:      base.Add(time.Minute),
			Last:       base.Add(2 * time.Minute),
			Interfaces: []string{"awdl0"},
		}})
		if _, emit = noise.flush(base.Add(4 * time.Minute)); emit {
			t.Fatal("the flush reported the same window twice")
		}
	})

	t.Run("a gap longer than the interval starts a new run", func(t *testing.T) {
		var noise noiseCoalescer
		var got []noiseSummary
		for _, offset := range []time.Duration{0, time.Minute, 2 * time.Minute, 17 * time.Minute} {
			summary, emit := noise.add([]string{"awdl0"}, base.Add(offset))
			if !emit {
				continue
			}
			got = append(got, summary)
		}
		want := []noiseSummary{{
			Count:      1,
			First:      base,
			Last:       base,
			Interfaces: []string{"awdl0"},
		}, {
			Count:      1,
			First:      base.Add(17 * time.Minute),
			Last:       base.Add(17 * time.Minute),
			Interfaces: []string{"awdl0"},
		}}
		assertSummaries(t, got, want)
	})
}

func assertSummaries(t *testing.T, got, want []noiseSummary) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d summaries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !sameSummary(got[i], want[i]) {
			t.Errorf("summary %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func sameSummary(got, want noiseSummary) bool {
	return got.Count == want.Count &&
		got.First.Equal(want.First) &&
		got.Last.Equal(want.Last) &&
		slices.Equal(got.Interfaces, want.Interfaces)
}
