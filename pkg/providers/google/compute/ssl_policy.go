package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type SSLPolicy struct {
	Metadata          defsecTypes.MisconfigMetadata
	Name              defsecTypes.StringValue
	Profile           defsecTypes.StringValue
	MinimumTLSVersion defsecTypes.StringValue
}
