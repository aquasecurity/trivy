package dns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

const ZoneRegistrationAuthTxt = "nifty-dns-verify="

type Record struct {
	Metadata defsecTypes.MisconfigMetadata
	Type     defsecTypes.StringValue
	Record   defsecTypes.StringValue
}
