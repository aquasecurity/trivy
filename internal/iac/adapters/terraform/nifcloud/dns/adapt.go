package dns

import (
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/dns"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
