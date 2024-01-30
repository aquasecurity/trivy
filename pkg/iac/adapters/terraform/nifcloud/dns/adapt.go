package dns

import (
	"github.com/aquasecurity/defsec/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/defsec/pkg/terraform"
)

func Adapt(modules terraform.Modules) dns.DNS {
	return dns.DNS{
		Records: adaptRecords(modules),
	}
}
