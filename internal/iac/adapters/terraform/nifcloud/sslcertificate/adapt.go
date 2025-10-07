package sslcertificate

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/nifcloud/sslcertificate"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
