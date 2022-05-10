package vpc

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/vpc"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result vpc.VPC) {

	result.DefaultVPCs = getDefaultVPCs()
	result.NetworkACLs = getNetworkACLs(cfFile)
	result.SecurityGroups = getSecurityGroups(cfFile)

	return result
}

func getDefaultVPCs() []vpc.DefaultVPC {
	// NOTE: it appears you can no longer create default VPCs via CF
	return nil
}
