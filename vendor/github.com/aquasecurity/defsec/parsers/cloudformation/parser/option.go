package parser

import (
	"io"
	"strings"
)

type Option func(p *Parser)

func OptionWithDebugWriter(w io.Writer) Option {
	return func(p *Parser) {
		p.debugWriter = w
	}
}

func ProvidedParametersOption(parameters string) Option {

	pairs := strings.Split(parameters, ",")
	params := make(map[string]Parameter)

	for _, pair := range pairs {
		pairParts := strings.Split(pair, "=")
		if len(pairParts) != 2 {
			continue
		}
		key := pairParts[0]
		val := pairParts[1]
		params[key] = Parameter{
			inner: parameterInner{
				Type:    "",
				Default: val,
			},
		}
	}

	return func(p *Parser) {
		p.parameters = params
	}
}
