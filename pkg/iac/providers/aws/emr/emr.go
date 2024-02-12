package emr

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	Metadata defsecTypes.Metadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata     defsecTypes.Metadata
	Name         defsecTypes.StringValue
	ReleaseLabel defsecTypes.StringValue
	ServiceRole  defsecTypes.StringValue
}

type SecurityConfiguration struct {
	Metadata      defsecTypes.Metadata
	Name          defsecTypes.StringValue
	Configuration defsecTypes.StringValue
}
