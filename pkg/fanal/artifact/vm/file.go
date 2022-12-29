package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk"
	"github.com/aquasecurity/trivy/pkg/log"
)

// default vmdk block size 64 KB
// If vm type vmdk max cache memory size 64 MB
const storageFILECacheSize = 1024

// ImageFile represents an local VM image file
type ImageFile struct {
	Storage

	filePath string
	file     *os.File
	reader   *io.SectionReader
}

func newFile(filePath string, storage Storage) (*ImageFile, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}

	c, err := lru.New[string, []byte](storageFILECacheSize)
	if err != nil {
		return nil, xerrors.Errorf("failed to create new lru cache: %w", err)
	}

	reader, err := disk.New(f, c)
	if err != nil {
		if errors.Is(err, vm.ErrUnsupportedType) {
			return nil, err
		}

		log.Logger.Debugf("VM image not detected: %s", err)
		log.Logger.Debugf("Assume raw image")
		fi, err := f.Stat()
		if err != nil {
			return nil, xerrors.Errorf("file stat error: %w", err)
		}
		reader = io.NewSectionReader(f, 0, fi.Size())
	}

	return &ImageFile{
		Storage: storage,

		filePath: filePath,
		file:     f,
		reader:   reader,
	}, nil
}

func (a *ImageFile) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	blobInfo, err := a.Analyze(ctx, a.reader)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("inspection error: %w", err)
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("cache calculation error: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return types.ArtifactReference{
		Name:    a.filePath,
		Type:    types.ArtifactVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a *ImageFile) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}

func (a *ImageFile) Clean(reference types.ArtifactReference) error {
	_ = a.file.Close()
	return a.cache.DeleteBlobs(reference.BlobIDs)
}
