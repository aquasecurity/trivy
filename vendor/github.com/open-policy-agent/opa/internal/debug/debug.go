package debug

import (
	"io"
	"io/ioutil"
	"log"
)

// Debug allows printing debug messages.
type Debug interface {
	// Printf prints, with a short file:line-number prefix
	Printf(format string, args ...interface{})
	// Writer returns the writer being written to, which may be
	// `ioutil.Discard` if no debug output is requested.
	Writer() io.Writer

	// Output allows tweaking the calldepth used for figuring
	// out which Go source file location is the interesting one,
	// i.e., which is included in the debug message. Useful for
	// setting up local helper methods.
	Output(calldepth int, s string) error
}

// New returns a new `Debug` outputting to the passed `sink`.
func New(sink io.Writer) Debug {
	flags := log.Lshortfile
	return log.New(sink, "", flags)
}

// Discard returns a new `Debug` that doesn't output anything.
// Note: We're not implementing the methods here with noop stubs
// since doing this way, we can propagate the "discarding" via
// `(Debug).Writer()`.
func Discard() Debug {
	return New(ioutil.Discard)
}
