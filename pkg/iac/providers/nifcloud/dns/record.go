package dns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const ZoneRegistrationAuthTxt = "nifty-dns-verify="

type Record struct {
	Metadata defsecTypes.Metadata
	Type     defsecTypes.StringValue
	Record   defsecTypes.StringValue
}
