package external

import (
	"context"
	"errors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/applier"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/local"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/config/all"
)

type ConfigScanner struct {
	cache         cache.FSCache
	policyPaths   []string
	dataPaths     []string
	namespaces    []string
	allowEmbedded bool
}

func NewConfigScanner(cacheDir string, policyPaths, dataPaths, namespaces []string, allowEmbedded bool) (*ConfigScanner, error) {
	// Initialize local cache
	cacheClient, err := cache.NewFSCache(cacheDir)
	if err != nil {
		return nil, err
	}

	return &ConfigScanner{
		cache:         cacheClient,
		policyPaths:   policyPaths,
		dataPaths:     dataPaths,
		namespaces:    namespaces,
		allowEmbedded: allowEmbedded,
	}, nil
}

func (s ConfigScanner) Scan(dir string) ([]types.Misconfiguration, error) {
	art, err := local.NewArtifact(dir, s.cache, artifact.Option{
		MisconfScannerOption: config.ScannerOption{
			PolicyPaths:             s.policyPaths,
			DataPaths:               s.dataPaths,
			Namespaces:              s.namespaces,
			DisableEmbeddedPolicies: !s.allowEmbedded,
		},
	})
	if err != nil {
		return nil, err
	}

	// Scan config files
	result, err := art.Inspect(context.Background())
	if err != nil {
		return nil, err
	}

	// Merge layers
	a := applier.NewApplier(s.cache)
	mergedLayer, err := a.ApplyLayers(result.ID, result.BlobIDs)
	if !errors.Is(err, analyzer.ErrUnknownOS) && !errors.Is(err, analyzer.ErrNoPkgsDetected) {
		return nil, err
	}

	// Do not assert successes and layer
	for i := range mergedLayer.Misconfigurations {
		mergedLayer.Misconfigurations[i].Layer = types.Layer{}
	}

	return mergedLayer.Misconfigurations, nil
}

func (s ConfigScanner) Close() error {
	return s.cache.Close()
}
