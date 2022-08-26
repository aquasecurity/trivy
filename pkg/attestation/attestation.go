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

// Envelope captures an envelope as described by the Secure Systems Lab
// Signing Specification.
// cf. https://github.com/secure-systems-lab/signing-spec/blob/master/envelope.md
type Envelope struct {
	dsse.Envelope
	// Base64-decoded payload
	Payload interface{}
}

func (e *Envelope) UnmarshalJSON(b []byte) error {
	var env dsse.Envelope
	err := json.NewDecoder(bytes.NewReader(b)).Decode(&env)
	if err != nil {
		return xerrors.Errorf("failed to decode as a dsse envelope: %w", err)
	}
	if env.PayloadType != in_toto.PayloadType {
		return xerrors.Errorf("invalid attestation payload type: %s", env.PayloadType)
	}

	e.Envelope = env

	decoded, err := base64.StdEncoding.DecodeString(e.Envelope.Payload)
	if err != nil {
		return xerrors.Errorf("failed to decode attestation payload: %w", err)
	}

	err = json.Unmarshal(decoded, &e.Payload)
	if err != nil {
		return err
	}

	return nil
}
