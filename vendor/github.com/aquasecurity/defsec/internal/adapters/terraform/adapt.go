package terraform

import (
	"github.com/aquasecurity/defsec/internal/adapters/terraform/aws"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/azure"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/cloudstack"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/digitalocean"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/github"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/google"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/kubernetes"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/openstack"
	"github.com/aquasecurity/defsec/internal/adapters/terraform/oracle"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/defsec/pkg/terraform"
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
