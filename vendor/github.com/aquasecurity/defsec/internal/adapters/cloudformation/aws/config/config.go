package config

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/config"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result config.Config) {

	result.ConfigurationAggregrator = getConfiguraionAggregator(cfFile)
	return result

}
