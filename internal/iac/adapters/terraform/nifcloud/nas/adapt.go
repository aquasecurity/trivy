package nas

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/nifcloud/nas"
	"github.com/aquasecurity/trivy/internal/iac/terraform"
)

func Adapt(modules terraform.Modules) nas.NAS {
	return nas.NAS{
		NASSecurityGroups: adaptNASSecurityGroups(modules),
		NASInstances:      adaptNASInstances(modules),
	}
}
