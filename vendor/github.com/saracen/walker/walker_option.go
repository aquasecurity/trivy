package walker

// WalkerOption is an option to configure Walk() behaviour.
type Option func(*walkerOptions) error

type walkerOptions struct {
	errorCallback func(pathname string, err error) error
}

// WithErrorCallback sets a callback to be used for error handling. Any error
// returned will halt the Walk function and return the error. If the callback
// returns nil Walk will continue.
func WithErrorCallback(callback func(pathname string, err error) error) Option {
	return func(o *walkerOptions) error {
		o.errorCallback = callback
		return nil
	}
}
