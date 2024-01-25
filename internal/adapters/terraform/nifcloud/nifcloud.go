package nifcloud

import (
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/computing"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/dns"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/nas"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/network"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/rdb"
	"github.com/aquasecurity/trivy/internal/adapters/terraform/nifcloud/sslcertificate"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/terraform"
)

func Adapt(modules terraform.Modules) nifcloud.Nifcloud {
	return nifcloud.Nifcloud{
		Computing:      computing.Adapt(modules),
		DNS:            dns.Adapt(modules),
		NAS:            nas.Adapt(modules),
		Network:        network.Adapt(modules),
		RDB:            rdb.Adapt(modules),
		SSLCertificate: sslcertificate.Adapt(modules),
	}
}
