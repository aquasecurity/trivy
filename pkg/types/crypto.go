package types

import (
	"time"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

// CryptoFinding reports a cryptographic asset that fails a built-in check.
type CryptoFinding struct {
	RuleID   string
	Title    string
	Severity string

	Asset     ftypes.CryptoDescriptor
	AssetName string
	FilePath  string                 `json:",omitempty"`
	Format    ftypes.CryptoKeyFormat `json:",omitempty"`
	Layer     ftypes.Layer           `json:",omitzero"`

	Evidence CryptoEvidence
}

// CryptoEvidence holds the values that make a check fail.
type CryptoEvidence struct {
	SignatureAlgorithm     string    `json:",omitempty"`
	SignatureAlgorithmOID  string    `json:",omitempty"`
	KeySize                int       `json:",omitempty"`
	Curve                  string    `json:",omitempty"`
	ClassicalSecurityLevel *int      `json:",omitempty"`
	NotAfter               time.Time `json:",omitzero"`
}
