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
		p.valuesFiles = paths
	}
}

func OptionWithValues(values ...string) Option {
	return func(p *Parser) {
		p.values = values
	}
}

func OptionWithFileValues(values ...string) Option {
	return func(p *Parser) {
		p.fileValues = values
	}
}

func OptionWithStringValues(values ...string) Option {
	return func(p *Parser) {
		p.stringValues = values
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
