package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) sam.SAM {
	return sam.SAM{
		APIs:          getApis(cfFile),
		HttpAPIs:      getHttpApis(cfFile),
		Functions:     getFunctions(cfFile),
		StateMachines: getStateMachines(cfFile),
		SimpleTables:  getSimpleTables(cfFile),
	}
}
