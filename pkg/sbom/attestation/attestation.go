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

	var predicate []byte

	switch attest.Predicate.(type) {
	case map[string]interface{}:
		// When cosign creates an attestation, it stores the predicate under a "Data" key.
		// https://github.com/sigstore/cosign/blob/938ad43f84aa183850014c8cc6d999f4b7ec5e8d/pkg/cosign/attestation/attestation.go#L39-L43
		data := attest.Predicate.(map[string]interface{})["Data"]
		predicate, err = json.Marshal(data)
		if err != nil {
			return sbom.SBOM{}, xerrors.Errorf("failed to marshal predicate: %w", err)
		}
	case string:
		predicate = []byte(attest.Predicate.(string))
	}

	return u.predicateUnmarshaler.Unmarshal(bytes.NewReader(predicate))
}

func NewUnmarshaler(predicateUnmarshaler sbom.Unmarshaler) sbom.Unmarshaler {
	return &Unmarshaler{
		predicateUnmarshaler: predicateUnmarshaler,
	}
}
