package acm

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ACM struct {
	Certificates []Certificate
}

type Certificate struct {
	Metadata           iacTypes.Metadata
	CertificateArn     iacTypes.StringValue
	DomainName         iacTypes.StringValue
	Status             iacTypes.StringValue
	IssuedAt           iacTypes.TimeValue
	NotAfter           iacTypes.TimeValue
	Type               iacTypes.StringValue
	KeyAlgorithm       iacTypes.StringValue
	SignatureAlgorithm iacTypes.StringValue
	UsedBy             []iacTypes.StringValue
	Issuer             iacTypes.StringValue
	Subject            iacTypes.StringValue
}
