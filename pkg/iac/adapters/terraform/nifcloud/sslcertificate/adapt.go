package sslcertificate

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/sslcertificate"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) sslcertificate.SSLCertificate {
	return sslcertificate.SSLCertificate{
		ServerCertificates: adaptServerCertificates(modules),
	}
}
