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

	switch attest.CosignPredicateData.(type) {
	case map[string]interface{}:
		predicateByte, err = json.Marshal(attest.CosignPredicateData)
		if err != nil {
			return sbom.SBOM{}, xerrors.Errorf("failed to marshal predicate: %w", err)
		}
	case string:
		predicateByte = []byte(attest.CosignPredicateData.(string))
	}

	return u.predicateUnmarshaler.Unmarshal(bytes.NewReader(predicateByte))
}

func NewUnmarshaler(predicateUnmarshaler sbom.Unmarshaler) sbom.Unmarshaler {
	return &Unmarshaler{
		predicateUnmarshaler: predicateUnmarshaler,
	}
}
