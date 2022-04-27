package terraform

import (
	"github.com/aquasecurity/defsec/adapters/terraform/aws"
	"github.com/aquasecurity/defsec/adapters/terraform/azure"
	"github.com/aquasecurity/defsec/adapters/terraform/cloudstack"
	"github.com/aquasecurity/defsec/adapters/terraform/digitalocean"
	"github.com/aquasecurity/defsec/adapters/terraform/github"
	"github.com/aquasecurity/defsec/adapters/terraform/google"
	"github.com/aquasecurity/defsec/adapters/terraform/kubernetes"
	"github.com/aquasecurity/defsec/adapters/terraform/openstack"
	"github.com/aquasecurity/defsec/adapters/terraform/oracle"
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/state"
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
		OpenStack:    openstack.Adapt(modules),
		Oracle:       oracle.Adapt(modules),
	}
}
