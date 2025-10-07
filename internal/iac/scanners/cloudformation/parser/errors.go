package parser

import (
	"fmt"
)

type InvalidContentError struct {
	source string
	err    error
}

func NewErrInvalidContent(source string, err error) *InvalidContentError {
	return &InvalidContentError{
		source: source,
		err:    err,
	}
}
func (e *InvalidContentError) Error() string {
	return fmt.Sprintf("Invalid content in file: %s. Error: %v", e.source, e.err)
}

func (e *InvalidContentError) Reason() error {
	return e.err
}
