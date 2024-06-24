package types

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type DetectedSecret ftypes.SecretFinding

func (DetectedSecret) findingType() FindingType { return FindingTypeSecret }
