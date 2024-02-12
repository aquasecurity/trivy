package dns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	Metadata   defsecTypes.Metadata
	DNSSec     DNSSec
	Visibility defsecTypes.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", defsecTypes.IgnoreCase)
}

type DNSSec struct {
	Metadata        defsecTypes.Metadata
	Enabled         defsecTypes.BoolValue
	DefaultKeySpecs []KeySpecs
}

type KeySpecs struct {
	Metadata  defsecTypes.Metadata
	Algorithm defsecTypes.StringValue
	KeyType   defsecTypes.StringValue
}
