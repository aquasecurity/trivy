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

type Statement struct {
	in_toto.StatementHeader
	Predicate    interface{} `json:"-"`
	RawPredicate interface{} `json:"predicate"`
}

// Decode returns the in-toto statement from the in-toto attestation.
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

	// When cosign creates an SBOM attestation, it stores the predicate under a "Data" key.
	// https://github.com/sigstore/cosign/blob/938ad43f84aa183850014c8cc6d999f4b7ec5e8d/pkg/cosign/attestation/attestation.go#L39-L43
	if _, found := st.RawPredicate.(map[string]interface{})["Data"]; found {
		st.Predicate = st.RawPredicate.(map[string]interface{})["Data"]
	} else {
		st.Predicate = st.RawPredicate
	}

	return st, nil
}
