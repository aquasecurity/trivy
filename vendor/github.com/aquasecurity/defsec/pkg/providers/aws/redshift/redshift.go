package redshift

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Redshift struct {
	Clusters       []Cluster
	SecurityGroups []SecurityGroup
}

type SecurityGroup struct {
	types.Metadata
	Description types.StringValue
}

type Cluster struct {
	types.Metadata
	Encryption      Encryption
	SubnetGroupName types.StringValue
}

type Encryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}
