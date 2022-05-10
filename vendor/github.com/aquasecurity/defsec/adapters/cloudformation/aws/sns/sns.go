package sns

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/sns"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result sns.SNS) {

	result.Topics = getTopics(cfFile)
	return result

}
