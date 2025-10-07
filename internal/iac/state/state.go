package state

import (
	"reflect"

	"github.com/aquasecurity/trivy/internal/iac/providers/aws"
	"github.com/aquasecurity/trivy/internal/iac/providers/azure"
	"github.com/aquasecurity/trivy/internal/iac/providers/cloudstack"
	"github.com/aquasecurity/trivy/internal/iac/providers/digitalocean"
	"github.com/aquasecurity/trivy/internal/iac/providers/github"
	"github.com/aquasecurity/trivy/internal/iac/providers/google"
	"github.com/aquasecurity/trivy/internal/iac/providers/kubernetes"
	"github.com/aquasecurity/trivy/internal/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/internal/iac/providers/openstack"
	"github.com/aquasecurity/trivy/internal/iac/providers/oracle"
	"github.com/aquasecurity/trivy/pkg/iac/rego/convert"
)

type State struct {
	AWS          aws.AWS
	Azure        azure.Azure
	CloudStack   cloudstack.CloudStack
	DigitalOcean digitalocean.DigitalOcean
	GitHub       github.GitHub
	Google       google.Google
	Kubernetes   kubernetes.Kubernetes
	OpenStack    openstack.OpenStack
	Oracle       oracle.Oracle
	Nifcloud     nifcloud.Nifcloud
}

func (a *State) ToRego() any {
	return convert.StructToRego(reflect.ValueOf(a))
}
