package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Compute struct {
	types.Metadata
	Instances []Instance
}

type Instance struct {
	types.Metadata
	UserData types.StringValue // not b64 encoded pls
}
