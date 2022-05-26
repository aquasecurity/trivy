package clock

import (
	"testing"
	"time"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

var c clock.Clock = clock.RealClock{}

// SetFakeTime sets a fake time for testing.
func SetFakeTime(t *testing.T, fakeTime time.Time) {
	c = clocktesting.NewFakeClock(fakeTime)
	t.Cleanup(func() {
		c = clock.RealClock{}
	})
}

func Now() time.Time {
	return c.Now()
}
