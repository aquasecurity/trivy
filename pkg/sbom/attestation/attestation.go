package attestation

import (
	"bytes"
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

	return u.predicateUnmarshaler.Unmarshal(bytes.NewReader(attest.Predicate.Data))
}

func NewUnmarshaler(predicateUnmarshaler sbom.Unmarshaler) sbom.Unmarshaler {
	return &Unmarshaler{
		predicateUnmarshaler: predicateUnmarshaler,
	}
}
