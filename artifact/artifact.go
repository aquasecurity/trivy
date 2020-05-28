package artifact

import (
	"context"

	"github.com/aquasecurity/fanal/types"
)

type Artifact interface {
	Inspect(ctx context.Context) (reference types.ArtifactReference, err error)
}
