package options

import "io"

type ConfigurableParser interface {
	SetDebugWriter(io.Writer)
}

type ParserOption func(s ConfigurableParser)

// ParserWithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func ParserWithDebug(w io.Writer) ParserOption {
	return func(s ConfigurableParser) {
		s.SetDebugWriter(w)
	}
}
