package artifact

import (
	"context"

	"github.com/aquasecurity/fanal/types"
)

type InspectOption struct {
	SkipDirectories []string
}

type Artifact interface {
	Inspect(ctx context.Context, option InspectOption) (reference types.ArtifactReference, err error)
}
