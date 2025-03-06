package ami

import iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

type AMI struct {
	Metadata iacTypes.Metadata
	Owners   iacTypes.StringValueList
}
