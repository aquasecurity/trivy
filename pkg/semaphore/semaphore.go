package semaphore

import "golang.org/x/sync/semaphore"

const defaultSize = 5

type options struct {
	size int64
}

type option func(*options)

func WithDefault(n int64) option {
	return func(opts *options) {
		opts.size = defaultSize
	}
}

func New(slow bool, opts ...option) *semaphore.Weighted {
	o := &options{size: defaultSize}
	for _, opt := range opts {
		opt(o)
	}
	if slow {
		// Process in series
		return semaphore.NewWeighted(1)
	}
	// Process in parallel
	return semaphore.NewWeighted(o.size)
}
