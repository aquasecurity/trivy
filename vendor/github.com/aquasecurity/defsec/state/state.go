package state

import (
	"reflect"

	"github.com/aquasecurity/defsec/providers/aws"
	"github.com/aquasecurity/defsec/providers/azure"
	"github.com/aquasecurity/defsec/providers/cloudstack"
	"github.com/aquasecurity/defsec/providers/digitalocean"
	"github.com/aquasecurity/defsec/providers/github"
	"github.com/aquasecurity/defsec/providers/google"
	"github.com/aquasecurity/defsec/providers/kubernetes"
	"github.com/aquasecurity/defsec/providers/openstack"
	"github.com/aquasecurity/defsec/providers/oracle"
	"github.com/aquasecurity/defsec/rego/convert"
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
}

func (s *State) ToRego() interface{} {
	return convert.StructToRego(reflect.ValueOf(s))
}
