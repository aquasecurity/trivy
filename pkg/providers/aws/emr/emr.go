package emr

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type EMR struct {
	Clusters              []Cluster
	SecurityConfiguration []SecurityConfiguration
}

type Cluster struct {
	Metadata defsecTypes.MisconfigMetadata
	Settings ClusterSettings
}

type ClusterSettings struct {
	Metadata     defsecTypes.MisconfigMetadata
	Name         defsecTypes.StringValue
	ReleaseLabel defsecTypes.StringValue
	ServiceRole  defsecTypes.StringValue
}

type SecurityConfiguration struct {
	Metadata      defsecTypes.MisconfigMetadata
	Name          defsecTypes.StringValue
	Configuration defsecTypes.StringValue
}
