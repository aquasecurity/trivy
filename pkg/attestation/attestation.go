package attestation

import (
	"bytes"
	"encoding/base64"
	"encoding/json"

	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"golang.org/x/xerrors"
)

// CosignPredicate specifies the format of the Custom Predicate.
// Cosign uses this structure when creating an SBOM attestation.
// cf. https://github.com/sigstore/cosign/blob/e0547cff64f98585a837a524ff77ff6b47ff5609/pkg/cosign/attestation/attestation.go#L39-L43
type CosignPredicate struct {
	Data interface{}
}

// Statement holds in-toto statement headers and the predicate.
type Statement in_toto.Statement

func (s *Statement) UnmarshalJSON(b []byte) error {
	var envelope dsse.Envelope
	err := json.NewDecoder(bytes.NewReader(b)).Decode(&envelope)
	if err != nil {
		return xerrors.Errorf("failed to decode as a dsse envelope: %w", err)
	}
	if envelope.PayloadType != in_toto.PayloadType {
		return xerrors.Errorf("invalid attestation payload type: %s", envelope.PayloadType)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return xerrors.Errorf("failed to decode attestation payload: %w", err)
	}

	statement := (*in_toto.Statement)(s)
	if err = json.NewDecoder(bytes.NewReader(decoded)).Decode(statement); err != nil {
		return xerrors.Errorf("failed to decode attestation payload as in-toto statement: %w", err)
	}

	return nil
}
