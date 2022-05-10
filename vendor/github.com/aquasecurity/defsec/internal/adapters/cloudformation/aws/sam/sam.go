package sam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (sam sam.SAM) {
	sam.APIs = getApis(cfFile)
	sam.HttpAPIs = getHttpApis(cfFile)
	sam.Functions = getFunctions(cfFile)
	sam.StateMachines = getStateMachines(cfFile)
	sam.SimpleTables = getSimpleTables(cfFile)
	return sam
}
