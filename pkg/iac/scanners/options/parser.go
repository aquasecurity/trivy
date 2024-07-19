package options

type ConfigurableParser interface {
	SetSkipRequiredCheck(bool)
}

type ParserOption func(s ConfigurableParser)

func ParserWithSkipRequiredCheck(skip bool) ParserOption {
	return func(s ConfigurableParser) {
		s.SetSkipRequiredCheck(skip)
	}
}
