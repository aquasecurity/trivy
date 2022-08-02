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

// Decode returns the in-toto statement from the in-toto attestation.
func Decode(r io.Reader) (in_toto.Statement, error) {

	var envelope dsse.Envelope
	err := json.NewDecoder(r).Decode(&envelope)
	if err != nil {
		return in_toto.Statement{}, xerrors.Errorf("failed to decode as a dsse envelope: %w", err)
	}
	if envelope.PayloadType != in_toto.PayloadType {
		return in_toto.Statement{}, xerrors.Errorf("invalid attestation payload type: %s", envelope.PayloadType)
	}

	decoded, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return in_toto.Statement{}, xerrors.Errorf("failed to decode attestation payload: %w", err)
	}

	var st in_toto.Statement
	err = json.NewDecoder(bytes.NewReader(decoded)).Decode(&st)
	if err != nil {
		return in_toto.Statement{}, xerrors.Errorf("failed to decode attestation payload as in-toto statement: %w", err)
	}
	return st, nil
}
