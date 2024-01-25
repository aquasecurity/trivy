package sslcertificate

import (
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/sslcertificate"
	"github.com/aquasecurity/trivy/pkg/terraform"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
