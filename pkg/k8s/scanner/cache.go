package scanner

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/log"
)

type resourceCache struct {
	dir string
}

func newResourceCache(baseDir string) (*resourceCache, error) {
	cacheDir := filepath.Join(baseDir, "k8s-artifacts")
	if err := os.MkdirAll(cacheDir, 0700); err != nil {
		return nil, err
	}
	return &resourceCache{dir: cacheDir}, nil
}

func (c *resourceCache) key(artifact *artifacts.Artifact) string {
	// Create a unique hash for the artifact based on its identifying fields.
	// Since K8s resources change versions, hashing the raw resource is a safe bet.
	h := sha256.New()
	h.Write(artifact.RawResource)
	return hex.EncodeToString(h.Sum(nil)) + ".json"
}

func (c *resourceCache) get(ctx context.Context, artifact *artifacts.Artifact) ([]report.Resource, bool) {
	path := filepath.Join(c.dir, c.key(artifact))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var res []report.Resource
	if err := json.Unmarshal(data, &res); err != nil {
		log.WarnContext(ctx, "Failed to unmarshal cached k8s artifact", log.Err(err))
		return nil, false
	}
	return res, true
}

func (c *resourceCache) put(ctx context.Context, artifact *artifacts.Artifact, res []report.Resource) {
	path := filepath.Join(c.dir, c.key(artifact))
	data, err := json.Marshal(res)
	if err != nil {
		log.WarnContext(ctx, "Failed to marshal k8s artifact for cache", log.Err(err))
		return
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		log.WarnContext(ctx, "Failed to write k8s artifact to cache", log.Err(err))
	}
}
