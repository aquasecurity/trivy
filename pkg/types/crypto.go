package types

import (
	"time"
)

// CryptoFinding reports a cryptographic asset that fails a built-in check.
type CryptoFinding struct {
	RuleID   string
	Title    string
	Severity string
	AssetID  string
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
