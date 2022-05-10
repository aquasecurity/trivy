package config

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/config"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result config.Config) {

	result.ConfigurationAggregrator = getConfiguraionAggregator(cfFile)
	return result

}
