package rpc

import (
	"time"

	"github.com/cenkalti/backoff"
	"github.com/twitchtv/twirp"

	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	maxRetries = 10
)

// Retry executes the function again using backoff until maxRetries or success
func Retry(f func() error) error {
	operation := func() error {
		err := f()
		if err != nil {
			twerr, ok := err.(twirp.Error)
			if !ok {
				return backoff.Permanent(err)
			}
			if twerr.Code() == twirp.Unavailable {
				return err
			}
			return backoff.Permanent(err)
		}
		return nil
	}

	b := backoff.WithMaxRetries(backoff.NewExponentialBackOff(), maxRetries)
	err := backoff.RetryNotify(operation, b, func(err error, _ time.Duration) {
		log.Logger.Warn(err)
		log.Logger.Info("Retrying HTTP request...")
	})
	if err != nil {
		return err
	}
	return nil
}
