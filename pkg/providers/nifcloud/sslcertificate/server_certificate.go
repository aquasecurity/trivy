package sslcertificate

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ServerCertificate struct {
	Metadata   defsecTypes.MisconfigMetadata
	Expiration defsecTypes.TimeValue
}
