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
func Retry(f func() error) error {
	operation := func() (any, error) {
		err := f()
		if err != nil {
			twerr, ok := err.(twirp.Error)
			if !ok {
				return nil, backoff.Permanent(err)
			}
			if twerr.Code() == twirp.Unavailable {
				return nil, err
			}
			return nil, backoff.Permanent(err)
		}
		return nil, nil
	}

	_, err := backoff.Retry(
		context.Background(),
		operation,
		backoff.WithBackOff(backoff.NewExponentialBackOff()),
		backoff.WithMaxTries(maxRetries),
		backoff.WithNotify(func(err error, _ time.Duration) {
			log.Warn("HTTP error", log.Err(err))
			log.Info("Retrying HTTP request...")
		}),
	)
	return err
}
