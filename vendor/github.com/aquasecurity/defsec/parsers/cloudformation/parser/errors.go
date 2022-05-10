package parser

import (
	"fmt"
	"strings"
)

type NotCloudFormationError struct {
	source string
}

func NewErrNotCloudFormation(source string) *NotCloudFormationError {
	return &NotCloudFormationError{
		source: source,
	}
}

func (e *NotCloudFormationError) Error() string {
	return fmt.Sprintf("The file %s is not CloudFormation", e.source)
}

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

type ParsingErrorsError struct {
	errs       []error
	errStrings []string
}

func NewErrParsingErrors(errs []error) *ParsingErrorsError {
	var errStrings []string
	for _, err := range errs {
		errStrings = append(errStrings, err.Error())
	}
	return &ParsingErrorsError{
		errs:       errs,
		errStrings: errStrings,
	}
}

func (e *ParsingErrorsError) Error() string {
	return fmt.Sprintf("There were parsing errors:\n %s", strings.Join(e.errStrings, "\n"))
}
