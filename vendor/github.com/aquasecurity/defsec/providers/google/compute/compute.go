package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Compute struct {
	types.Metadata
	Disks           []Disk
	Networks        []Network
	SSLPolicies     []SSLPolicy
	ProjectMetadata ProjectMetadata
	Instances       []Instance
}
