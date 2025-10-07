package dns

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/nifcloud/dns"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
