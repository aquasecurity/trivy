package ec2

import "github.com/aquasecurity/defsec/parsers/types"

type EC2 struct {
	types.Metadata
	Instances []Instance
}
