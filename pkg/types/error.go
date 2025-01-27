package types

import (
	"fmt"
)

type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// UserError represents an error with a user-friendly message.
type UserError struct {
	Message string
}

func (e *UserError) Error() string {
	return e.Message
}
