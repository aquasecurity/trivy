package custom

import (
	"time"
)

type ErrorCallback func(pathname string, err error) error

// Option is a struct that allows defining a custom behavior.
// This option is only available when Trivy is used as an imported library and not through CLI flags.
type Option struct {
	// Delay is the amount of time to wait between each file walk.
	// Default: 0 sec
	Delay time.Duration

	// ErrorCallback is a function that allows users to define a custom error handling behavior while walking the filesystem.
	// If not defined, the default behavior is to halt traversal on any error.
	ErrorCallback ErrorCallback
}
