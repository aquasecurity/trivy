package dns

import (
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/trivy/pkg/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
