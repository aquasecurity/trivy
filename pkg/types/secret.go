package types

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

type DetectedSecret ftypes.SecretFinding

func (DetectedSecret) FindingType() FindingType { return FindingTypeSecret }
