package wait

import (
	"context"
	"io/ioutil"
	"strings"
	"time"
)

// Implement interface
var _ Strategy = (*LogStrategy)(nil)

// LogStrategy will wait until a given log entry shows up in the docker logs
type LogStrategy struct {
	// all Strategies should have a startupTimeout to avoid waiting infinitely
	startupTimeout time.Duration

	// additional properties
	Log          string
	Occurrence   int
	PollInterval time.Duration
}

// NewLogStrategy constructs with polling interval of 100 milliseconds and startup timeout of 60 seconds by default
func NewLogStrategy(log string) *LogStrategy {
	return &LogStrategy{
		startupTimeout: defaultStartupTimeout(),
		Log:            log,
		Occurrence:     1,
		PollInterval:   defaultPollInterval(),
	}

}

// fluent builders for each property
// since go has neither covariance nor generics, the return type must be the type of the concrete implementation
// this is true for all properties, even the "shared" ones like startupTimeout

// WithStartupTimeout can be used to change the default startup timeout
func (ws *LogStrategy) WithStartupTimeout(startupTimeout time.Duration) *LogStrategy {
	ws.startupTimeout = startupTimeout
	return ws
}

// WithPollInterval can be used to override the default polling interval of 100 milliseconds
func (ws *LogStrategy) WithPollInterval(pollInterval time.Duration) *LogStrategy {
	ws.PollInterval = pollInterval
	return ws
}

func (ws *LogStrategy) WithOccurrence(o int) *LogStrategy {
	// the number of occurrence needs to be positive
	if o <= 0 {
		o = 1
	}
	ws.Occurrence = o
	return ws
}

// ForLog is the default construction for the fluid interface.
//
// For Example:
// wait.
//     ForLog("some text").
//     WithPollInterval(1 * time.Second)
func ForLog(log string) *LogStrategy {
	return NewLogStrategy(log)
}

// WaitUntilReady implements Strategy.WaitUntilReady
func (ws *LogStrategy) WaitUntilReady(ctx context.Context, target StrategyTarget) (err error) {
	// limit context to startupTimeout
	ctx, cancelContext := context.WithTimeout(ctx, ws.startupTimeout)
	defer cancelContext()

LOOP:
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			reader, err := target.Logs(ctx)

			if err != nil {
				time.Sleep(ws.PollInterval)
				continue
			}
			b, err := ioutil.ReadAll(reader)
			logs := string(b)
			if strings.Count(logs, ws.Log) >= ws.Occurrence {
				break LOOP
			} else {
				time.Sleep(ws.PollInterval)
				continue
			}
		}
	}

	return nil
}
