package compute

type Compute struct {
	Disks           []Disk
	Networks        []Network
	SSLPolicies     []SSLPolicy
	ProjectMetadata ProjectMetadata
	Instances       []Instance
}
