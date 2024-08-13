package options

type ConfigurableParser interface {
}

type ParserOption func(s ConfigurableParser)
