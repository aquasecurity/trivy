package compute

import "github.com/aquasecurity/defsec/parsers/types"

type SSLPolicy struct {
	types.Metadata
	Name              types.StringValue
	Profile           types.StringValue
	MinimumTLSVersion types.StringValue
}
