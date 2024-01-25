package state

import (
	"reflect"

	"github.com/aquasecurity/trivy/pkg/providers/aws"
	"github.com/aquasecurity/trivy/pkg/providers/azure"
	"github.com/aquasecurity/trivy/pkg/providers/cloudstack"
	"github.com/aquasecurity/trivy/pkg/providers/digitalocean"
	"github.com/aquasecurity/trivy/pkg/providers/github"
	"github.com/aquasecurity/trivy/pkg/providers/google"
	"github.com/aquasecurity/trivy/pkg/providers/kubernetes"
	"github.com/aquasecurity/trivy/pkg/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/providers/openstack"
	"github.com/aquasecurity/trivy/pkg/providers/oracle"
	"github.com/aquasecurity/trivy/pkg/rego/convert"
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

func (a *State) ToRego() interface{} {
	return convert.StructToRego(reflect.ValueOf(a))
}
