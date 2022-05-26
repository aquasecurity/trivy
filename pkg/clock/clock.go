package clock

import (
	"time"

	"k8s.io/utils/clock"
	"k8s.io/utils/clock/testing"
)

var c clock.Clock = clock.RealClock{}

// SetFakeTime sets a fake time. The caller must call the returned cleanup function.
func SetFakeTime(t time.Time) func() {
	c = testing.NewFakeClock(t)
	return func() {
		c = clock.RealClock{}
	}
}

func Now() time.Time {
	return c.Now()
}
