package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Compute struct {
	Instances []Instance
}

type Instance struct {
	Metadata defsecTypes.MisconfigMetadata
	UserData defsecTypes.StringValue // not b64 encoded pls
}
