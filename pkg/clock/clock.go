package clock

import (
	"context"
	"time"

	"k8s.io/utils/clock"
	clocktesting "k8s.io/utils/clock/testing"
)

type (
	RealClock = clock.RealClock
	FakeClock = clocktesting.FakeClock
)

// clockKey is the context key for clock. It is unexported to prevent collisions with context keys defined in
// other packages.
type clockKey struct{}

// processStart records when the Trivy process started. It defaults to the time
// this package is initialized and should be set explicitly via SetProcessStart
// as early as possible (e.g. from main's init), so it reflects the true process
// start even when callers that read it are imported lazily.
var processStart = RealClock{}.Now()

// SetProcessStart records the process start time. It is meant to be called once,
// before scanning begins.
func SetProcessStart(t time.Time) {
	processStart = t
}

// ProcessStart returns the recorded process start time.
func ProcessStart() time.Time {
	return processStart
}

// With returns a new context with the given time.
func With(ctx context.Context, t time.Time) context.Context {
	c := clocktesting.NewFakeClock(t)
	return context.WithValue(ctx, clockKey{}, c)
}

// Now returns the current time.
func Now(ctx context.Context) time.Time {
	return Clock(ctx).Now()
}

// Clock returns the clock from the context.
func Clock(ctx context.Context) clock.Clock {
	t, ok := ctx.Value(clockKey{}).(clock.Clock)
	if !ok {
		return RealClock{}
	}
	return t
}
