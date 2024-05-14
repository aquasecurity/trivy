package vm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/opencontainers/go-digest"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
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
		return nil, fmt.Errorf("file open error: %w", err)
	}

	c, err := lru.New[string, []byte](storageFILECacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create new lru cache: %w", err)
	}

	reader, err := disk.New(f, c)
	if err != nil {
		if errors.Is(err, vm.ErrUnsupportedType) {
			return nil, err
		}

		logger := log.WithPrefix("vm")
		logger.Debug("VM image not detected", log.Err(err))
		logger.Debug("Assume raw image")
		fi, err := f.Stat()
		if err != nil {
			return nil, fmt.Errorf("file stat error: %w", err)
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

func (a *ImageFile) Inspect(ctx context.Context) (artifact.Reference, error) {
	blobInfo, err := a.Analyze(ctx, a.reader)
	if err != nil {
		return artifact.Reference{}, fmt.Errorf("inspection error: %w", err)
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return artifact.Reference{}, fmt.Errorf("cache calculation error: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return artifact.Reference{}, fmt.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	return artifact.Reference{
		Name:    a.filePath,
		Type:    artifact.TypeVM,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a *ImageFile) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", fmt.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", fmt.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}

func (a *ImageFile) Clean(reference artifact.Reference) error {
	_ = a.file.Close()
	return a.cache.DeleteBlobs(reference.BlobIDs)
}
