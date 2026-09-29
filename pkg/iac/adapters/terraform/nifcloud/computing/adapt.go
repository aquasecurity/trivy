package computing

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

func Adapt(modules terraform.Modules) computing.Computing {

	sgAdapter := sgAdapter{sgRuleIDs: modules.GetChildResourceIDMapByType("nifcloud_security_group_rule")}

	return computing.Computing{
		SecurityGroups: sgAdapter.adaptSecurityGroups(modules),
		Instances:      adaptInstances(modules),
	}
}
