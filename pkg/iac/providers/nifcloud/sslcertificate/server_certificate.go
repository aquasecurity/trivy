package sslcertificate

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ServerCertificate struct {
	Metadata   defsecTypes.Metadata
	Expiration defsecTypes.TimeValue
}
