package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type SSLPolicy struct {
	Metadata          defsecTypes.Metadata
	Name              defsecTypes.StringValue
	Profile           defsecTypes.StringValue
	MinimumTLSVersion defsecTypes.StringValue
}
