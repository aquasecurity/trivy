package cache

import "github.com/aquasecurity/trivy/pkg/fanal/cache"

func NopCache(ac cache.ArtifactCache) cache.Cache {
	return nopCache{ArtifactCache: ac}
}

type nopCache struct {
	cache.ArtifactCache
	cache.LocalArtifactCache
}

func (nopCache) Close() error {
	return nil
}
