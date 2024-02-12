package options

import "io"

type ConfigurableParser interface {
	SetDebugWriter(io.Writer)
	SetSkipRequiredCheck(bool)
}

type ParserOption func(s ConfigurableParser)

func ParserWithSkipRequiredCheck(skip bool) ParserOption {
	return func(s ConfigurableParser) {
		s.SetSkipRequiredCheck(skip)
	}
}

// ParserWithDebug specifies an io.Writer for debug logs - if not set, they are discarded
func ParserWithDebug(w io.Writer) ParserOption {
	return func(s ConfigurableParser) {
		s.SetDebugWriter(w)
	}
}
