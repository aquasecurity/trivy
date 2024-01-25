package nifcloud

import (
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/computing"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/dns"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/nas"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/rdb"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud/sslcertificate"
)

type Nifcloud struct {
	Computing      computing.Computing
	DNS            dns.DNS
	NAS            nas.NAS
	Network        network.Network
	RDB            rdb.RDB
	SSLCertificate sslcertificate.SSLCertificate
}
