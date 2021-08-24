package external

import (
	"context"
	"errors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
)

type ConfigScanner struct {
	cache       cache.FSCache
	policyPaths []string
	dataPaths   []string
	namespaces  []string
}

func NewConfigScanner(cacheDir string, policyPaths, dataPaths, namespaces []string) (*ConfigScanner, error) {
	// Initialize local cache
	cacheClient, err := cache.NewFSCache(cacheDir)
	if err != nil {
		return nil, err
	}

	return &ConfigScanner{
		cache:       cacheClient,
		policyPaths: policyPaths,
		dataPaths:   dataPaths,
		namespaces:  namespaces,
	}, nil
}

func (s ConfigScanner) Scan(dir string) ([]types.Misconfiguration, error) {
	art, err := local.NewArtifact(dir, s.cache, nil, nil, config.ScannerOption{
		PolicyPaths: s.policyPaths,
		DataPaths:   s.dataPaths,
		Namespaces:  s.namespaces,
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
