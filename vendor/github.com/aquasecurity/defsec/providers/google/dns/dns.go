package dns

import "github.com/aquasecurity/defsec/parsers/types"

type DNS struct {
	types.Metadata
	ManagedZones []ManagedZone
}

type ManagedZone struct {
	types.Metadata
	DNSSec DNSSec
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
