package parser

type ConfigurableHelmParser interface {
	SetValuesFile(...string)
	SetValues(...string)
	SetFileValues(...string)
	SetStringValues(...string)
	SetAPIVersions(...string)
	SetKubeVersion(string)
}

type Option func(p *Parser)

func OptionWithValuesFile(paths ...string) Option {
	return func(p *Parser) {
		p.valueOpts.ValueFiles = paths
	}
}

func OptionWithValues(values ...string) Option {
	return func(p *Parser) {
		p.valueOpts.Values = values
	}
}

func OptionWithFileValues(values ...string) Option {
	return func(p *Parser) {
		p.valueOpts.FileValues = values
	}
}

func OptionWithStringValues(values ...string) Option {
	return func(p *Parser) {
		p.valueOpts.StringValues = values
	}
}

func OptionWithAPIVersions(values ...string) Option {
	return func(p *Parser) {
		p.apiVersions = values
	}
}

func OptionWithKubeVersion(value string) Option {
	return func(p *Parser) {
		p.kubeVersion = value
	}
}
