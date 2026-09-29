package ec2

import iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

type RequestedAMI struct {
	Metadata iacTypes.Metadata
	Owners   iacTypes.StringValueList
}
