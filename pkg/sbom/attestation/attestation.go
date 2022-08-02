package attestation

import (
	"bytes"
	"encoding/json"
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

type Unmarshaler struct {
	predicateUnmarshaler sbom.Unmarshaler
}

func (u Unmarshaler) Unmarshal(r io.Reader) (sbom.SBOM, error) {
	attest, err := attestation.Decode(r)
	if err != nil {
		return sbom.SBOM{}, xerrors.Errorf("failed to decode attestation: %w", err)
	}

	var predicateByte []byte

	// When cosign creates an attestation, it stores the predicate under a "Data" key.
	// https://github.com/sigstore/cosign/blob/938ad43f84aa183850014c8cc6d999f4b7ec5e8d/pkg/cosign/attestation/attestation.go#L39-L43
	predicate := attest.Predicate.(map[string]interface{})["Data"]

	switch predicate.(type) {
	case map[string]interface{}:
		predicateByte, err = json.Marshal(predicate)
		if err != nil {
			return sbom.SBOM{}, xerrors.Errorf("failed to marshal predicate: %w", err)
		}
	case string:
		predicateByte = []byte(attest.Predicate.(string))
	}

	return u.predicateUnmarshaler.Unmarshal(bytes.NewReader(predicateByte))
}

func NewUnmarshaler(predicateUnmarshaler sbom.Unmarshaler) sbom.Unmarshaler {
	return &Unmarshaler{
		predicateUnmarshaler: predicateUnmarshaler,
	}
}
