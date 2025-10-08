package nas

import (
	"github.com/aquasecurity/trivy/internal/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/nas"
)

func Adapt(modules terraform.Modules) nas.NAS {
	return nas.NAS{
		NASSecurityGroups: adaptNASSecurityGroups(modules),
		NASInstances:      adaptNASInstances(modules),
	}
}
