package dns

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	Metadata   iacTypes.Metadata
	DNSSec     DNSSec
	Visibility iacTypes.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", iacTypes.IgnoreCase)
}

type DNSSec struct {
	Metadata        iacTypes.Metadata
	Enabled         iacTypes.BoolValue
	DefaultKeySpecs []KeySpecs
}

type KeySpecs struct {
	Metadata  iacTypes.Metadata
	Algorithm iacTypes.StringValue
	KeyType   iacTypes.StringValue
}
