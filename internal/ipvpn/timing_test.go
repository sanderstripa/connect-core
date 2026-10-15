package ipvpn

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestTimingReportsWaitDistribution(t *testing.T) {
	var timing Timing
	for _, d := range []time.Duration{0, time.Millisecond, 20 * time.Millisecond, 60 * time.Millisecond} {
		timing.Observe(d)
	}
	var out bytes.Buffer
	timing.Report(&out, "queue")
	for _, want := range []string{"samples=4", "average_us=20250", "max_us=60000", "over_1ms=3", "over_10ms=2", "over_50ms=1"} {
		if !strings.Contains(out.String(), want) {
			t.Fatal(out.String())
		}
	}
}
