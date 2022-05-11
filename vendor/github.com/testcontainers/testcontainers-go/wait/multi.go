package wait

import (
	"context"
	"fmt"
	"time"
)

// Implement interface
var _ Strategy = (*MultiStrategy)(nil)

type MultiStrategy struct {
	// all Strategies should have a startupTimeout to avoid waiting infinitely
	startupTimeout time.Duration

	// additional properties
	Strategies []Strategy
}

func (ms *MultiStrategy) WithStartupTimeout(startupTimeout time.Duration) *MultiStrategy {
	ms.startupTimeout = startupTimeout
	return ms
}

func ForAll(strategies ...Strategy) *MultiStrategy {
	return &MultiStrategy{
		startupTimeout: defaultStartupTimeout(),
		Strategies:     strategies,
	}
}

func (ms *MultiStrategy) WaitUntilReady(ctx context.Context, target StrategyTarget) (err error) {
	ctx, cancelContext := context.WithTimeout(ctx, ms.startupTimeout)
	defer cancelContext()

	if len(ms.Strategies) == 0 {
		return fmt.Errorf("no wait strategy supplied")
	}

	for _, strategy := range ms.Strategies {
		err := strategy.WaitUntilReady(ctx, target)
		if err != nil {
			return err
		}
	}
	return nil
}
