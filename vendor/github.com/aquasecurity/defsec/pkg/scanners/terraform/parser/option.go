package parser

import (
	"github.com/aquasecurity/defsec/pkg/scanners/options"
)

type ConfigurableTerraformParser interface {
	options.ConfigurableParser
	SetTFVarsPaths(...string)
	SetStopOnHCLError(bool)
	SetWorkspaceName(string)
	SetAllowDownloads(bool)
}

type Option func(p ConfigurableTerraformParser)

func OptionWithTFVarsPaths(paths ...string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetTFVarsPaths(paths...)
		}
	}
}

func OptionStopOnHCLError(stop bool) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetStopOnHCLError(stop)
		}
	}
}

func OptionWithWorkspaceName(workspaceName string) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetWorkspaceName(workspaceName)
		}
	}
}

func OptionWithDownloads(allowed bool) options.ParserOption {
	return func(p options.ConfigurableParser) {
		if tf, ok := p.(ConfigurableTerraformParser); ok {
			tf.SetAllowDownloads(allowed)
		}
	}
}
