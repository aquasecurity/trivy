package cache

import "github.com/aquasecurity/trivy/pkg/fanal/types"

type NopCache struct{}

func NewNopCache() NopCache                                     { return NopCache{} }
func (NopCache) GetArtifact(string) (types.ArtifactInfo, error) { return types.ArtifactInfo{}, nil }
func (NopCache) GetBlob(string) (types.BlobInfo, error)         { return types.BlobInfo{}, nil }
func (NopCache) Close() error                                   { return nil }
func (NopCache) Clear() error                                   { return nil }
