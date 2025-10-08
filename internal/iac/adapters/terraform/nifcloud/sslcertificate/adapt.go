package sslcertificate

import (
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/sslcertificate"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
