package cloudstack

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/cloudstack/compute"
)

type CloudStack struct {
	Compute compute.Compute
}
