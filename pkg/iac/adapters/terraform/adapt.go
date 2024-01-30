package terraform

import (
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/aws"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/cloudstack"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/digitalocean"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/github"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/google"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/openstack"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/oracle"
)

func Adapt(modules terraform.Modules) *state.State {
	return &state.State{
		AWS:          aws.Adapt(modules),
		Azure:        azure.Adapt(modules),
		CloudStack:   cloudstack.Adapt(modules),
		DigitalOcean: digitalocean.Adapt(modules),
		GitHub:       github.Adapt(modules),
		Google:       google.Adapt(modules),
		Kubernetes:   kubernetes.Adapt(modules),
		Nifcloud:     nifcloud.Adapt(modules),
		OpenStack:    openstack.Adapt(modules),
		Oracle:       oracle.Adapt(modules),
	}
}
