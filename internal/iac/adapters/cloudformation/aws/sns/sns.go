package sns

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/sns"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts a SNS instance
func Adapt(cfFile parser.FileContext) sns.SNS {
	return sns.SNS{
		Topics: getTopics(cfFile),
	}
}
