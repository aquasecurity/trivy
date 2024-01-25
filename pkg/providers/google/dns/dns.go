package dns

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	Metadata   defsecTypes.MisconfigMetadata
	DNSSec     DNSSec
	Visibility defsecTypes.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", defsecTypes.IgnoreCase)
}

type DNSSec struct {
	Metadata        defsecTypes.MisconfigMetadata
	Enabled         defsecTypes.BoolValue
	DefaultKeySpecs []KeySpecs
}

type KeySpecs struct {
	Metadata  defsecTypes.MisconfigMetadata
	Algorithm defsecTypes.StringValue
	KeyType   defsecTypes.StringValue
}
