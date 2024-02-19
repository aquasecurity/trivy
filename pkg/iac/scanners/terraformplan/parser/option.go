package parser

import "io"

type Option func(p *Parser)

func OptionWithDebugWriter(w io.Writer) Option {
	return func(p *Parser) {
		p.debugWriter = w
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(p *Parser) {
		p.stopOnHCLError = stop
	}
}
