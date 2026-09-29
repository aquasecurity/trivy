package cache

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type NopCache struct{}

func NewNopCache() NopCache { return NopCache{} }
func (NopCache) GetArtifact(context.Context, string) (types.ArtifactInfo, error) {
	return types.ArtifactInfo{}, nil
}
func (NopCache) GetBlob(context.Context, string) (types.BlobInfo, error) {
	return types.BlobInfo{}, nil
}
func (NopCache) Close() error                { return nil }
func (NopCache) Clear(context.Context) error { return nil }
