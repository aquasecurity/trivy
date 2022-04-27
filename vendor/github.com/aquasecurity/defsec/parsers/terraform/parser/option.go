package parser

import "io"

type Option func(p *parser)

func OptionWithDebugWriter(w io.Writer) Option {
	return func(p *parser) {
		p.debugWriter = w
	}
}

func OptionWithTFVarsPaths(paths []string) Option {
	return func(p *parser) {
		p.tfvarsPaths = paths
	}
}

func OptionStopOnHCLError(stop bool) Option {
	return func(p *parser) {
		p.stopOnHCLError = stop
	}
}

func OptionWithWorkspaceName(workspaceName string) Option {
	return func(p *parser) {
		p.workspaceName = workspaceName
	}
}

func OptionWithDownloads(allowed bool) Option {
	return func(p *parser) {
		p.allowDownloads = allowed
	}
}
