package vm

import (
	"context"
	"io"

	lru "github.com/hashicorp/golang-lru/v2"
	ebsfile "github.com/masahiro331/go-ebs-file"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

// default block size 512 KB
// Max cache memory size 64 MB
const storageEBSCacheSize = 128

// EBS represents an artifact for AWS EBS snapshots
type EBS struct {
	Storage
	snapshotID string
	ebs        ebsfile.EBSAPI
}

func newEBS(snapshotID string, vm Storage, region string) (*EBS, error) {
	ebs, err := ebsfile.New(ebsfile.Option{
		AwsRegion: region,
	})
	if err != nil {
		return nil, xerrors.Errorf("new ebsfile error: %w", err)
	}

	return &EBS{
		Storage:    vm,
		snapshotID: snapshotID,
		ebs:        ebs,
	}, nil
}

func (a *EBS) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	sr, err := a.openEBS(ctx)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("EBS open error: %w", err)
	}

	cacheKey, err := a.calcCacheKey(a.snapshotID)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("cache key calculation error: %w", err)
	}

	if a.hasCache(cacheKey) {
		return types.ArtifactReference{
			Name:    a.snapshotID,
			Type:    types.ArtifactVM,
			ID:      cacheKey, // use a cache key as pseudo artifact ID
			BlobIDs: []string{cacheKey},
		}, nil
	}

	blobInfo, err := a.Analyze(ctx, sr)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("inspection error: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return types.ArtifactReference{
		Name:    a.snapshotID,
		Type:    types.ArtifactVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a *EBS) openEBS(ctx context.Context) (*io.SectionReader, error) {
	c, err := lru.New[string, []byte](storageEBSCacheSize)
	if err != nil {
		return nil, xerrors.Errorf("lru cache error: %w", err)
	}

	r, err := ebsfile.Open(a.snapshotID, ctx, c, a.ebs)
	if err != nil {
		return nil, xerrors.Errorf("EBS error: %w", err)
	}
	return r, nil
}

func (a *EBS) Clean(_ types.ArtifactReference) error {
	return nil
}

func (a *EBS) SetEBS(ebs ebsfile.EBSAPI) {
	a.ebs = ebs
}

func (a *EBS) calcCacheKey(key string) (string, error) {
	s, err := cache.CalcKey(key, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("failed to calculate cache key: %w", err)
	}
	return s, nil
}

func (a *EBS) hasCache(cacheKey string) bool {
	_, missingCacheKeys, err := a.cache.MissingBlobs(cacheKey, []string{cacheKey})
	if err != nil {
		log.Logger.Debugf("Unable to query missing cache: %s", err)
		return false
	}

	// Cache exists
	if len(missingCacheKeys) == 0 {
		return true
	}

	log.Logger.Debugf("Missing virtual machine cache: %s", cacheKey)
	return false
}
