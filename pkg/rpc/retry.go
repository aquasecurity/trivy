package rpc

import (
	"context"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	maxRetries = 10
)

// Retry executes the function again using backoff until maxRetries or success
func Retry[T any](ctx context.Context, f func() (T, error)) (T, error) {
	operation := func() (T, error) {
		res, err := f()
		if err != nil {
			var zero T
			twerr, ok := err.(twirp.Error)
			if !ok {
				return zero, backoff.Permanent(err)
			}
			if twerr.Code() == twirp.Unavailable {
				return zero, err
			}
			return zero, backoff.Permanent(err)
		}
		return res, nil
	}

	return backoff.Retry(
		ctx,
		operation,
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxTries(maxRetries),
		backoff.WithNotify(func(err error, _ time.Duration) {
			log.Warn("HTTP error", log.Err(err))
			log.Info("Retrying HTTP request...")
		}),
	)
}
