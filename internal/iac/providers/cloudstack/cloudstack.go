package cloudstack

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/cloudstack/compute"
)

type CloudStack struct {
	Compute compute.Compute
}
