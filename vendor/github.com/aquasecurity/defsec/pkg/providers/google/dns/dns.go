package dns

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type DNS struct {
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	types.Metadata
	DNSSec     DNSSec
	Visibility types.StringValue
}

func (m ManagedZone) IsPrivate() bool {
	return m.Visibility.EqualTo("private", types.IgnoreCase)
}

type DNSSec struct {
	types.Metadata
	Enabled         types.BoolValue
	DefaultKeySpecs KeySpecs
}

type KeySpecs struct {
	types.Metadata
	KeySigningKey  Key
	ZoneSigningKey Key
}

type Key struct {
	types.Metadata
	Algorithm types.StringValue
}
