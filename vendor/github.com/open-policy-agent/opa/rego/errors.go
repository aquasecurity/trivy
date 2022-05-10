package rego

// HaltError is an error type to return from a custom function implementation
// that will abort the evaluation process (analogous to topdown.Halt).
type HaltError struct {
	err error
}

// Error delegates to the wrapped error
func (h *HaltError) Error() string {
	return h.err.Error()
}

// NewHaltError wraps an error such that the evaluation process will stop
// when it occurs.
func NewHaltError(err error) error {
	return &HaltError{err: err}
}

// ErrorDetails interface is satisfied by an error that provides further
// details.
type ErrorDetails interface {
	Lines() []string
}
