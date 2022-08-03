package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"golang.org/x/xerrors"
)

// CosignPredicate specifies the format of the Custom Predicate.
// Cosign uses this structure when creating an SBOM attestation.
type CosignPredicate struct {
	Data json.RawMessage
}

// Statement holds statement headers and the predicate.
type Statement struct {
	PredicateType string `json:"predicateType"`

	// Predicate contains type specific metadata.
	Predicate CosignPredicate `json:"predicate"`
}

// Decode returns the statement from the attestation.
func Decode(r io.Reader) (Statement, error) {

	var envelope dsse.Envelope
	err := json.NewDecoder(r).Decode(&envelope)
	if err != nil {
		return Statement{}, xerrors.Errorf("failed to decode as a dsse envelope: %w", err)
	}
	if envelope.PayloadType != in_toto.PayloadType {
		return Statement{}, xerrors.Errorf("invalid attestation payload type: %s", envelope.PayloadType)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return Statement{}, xerrors.Errorf("failed to decode attestation payload: %w", err)
	}

	var st Statement
	err = json.NewDecoder(bytes.NewReader(decoded)).Decode(&st)
	if err != nil {
		return Statement{}, xerrors.Errorf("failed to decode attestation payload as in-toto statement: %w", err)
	}

	return st, nil
}
