package vm

import (
	"context"
	"io"
	"strings"

	"cloud.google.com/go/storage"
	lru "github.com/hashicorp/golang-lru/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/vm/disk"
)

type GCS struct {
	Storage
	bucket string
	object string
}

func newGCS(target string, vm Storage) (*GCS, error) {
	if !strings.HasPrefix(target, "gs://") {
		return nil, xerrors.New("the format of the target is not valid")
	}
	splitted := strings.SplitN(target[5:], "/", 2)
	if len(splitted) != 2 {
		return nil, xerrors.New("the format of the target is not valid")
	}

	return &GCS{
		Storage: vm,
		bucket:  splitted[0],
		object:  splitted[1],
	}, nil
}

func (a *GCS) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	sr, err := a.openGCS(ctx)
	if err != nil {
		return types.ArtifactReference{}, err
	}

	cacheKey, err := a.calcCacheKey()
	if err != nil {
		return types.ArtifactReference{}, err
	}

	if a.hasCache(cacheKey) {
		return types.ArtifactReference{
			Name:    a.bucket + "/" + a.object,
			Type:    types.ArtifactVM,
			ID:      cacheKey,
			BlobIDs: []string{cacheKey},
		}, nil
	}

	blobInfo, err := a.Analyze(ctx, sr)
	if err != nil {
		return types.ArtifactReference{}, err
	}
	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, err
	}

	return types.ArtifactReference{
		Name:    a.bucket + "/" + a.object,
		Type:    types.ArtifactVM,
		ID:      cacheKey,
		BlobIDs: []string{cacheKey},
	}, nil
}

func (a *GCS) Clean(_ types.ArtifactReference) error {
	return nil
}

func (a *GCS) openGCS(ctx context.Context) (*io.SectionReader, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	handle := client.Bucket(a.bucket).Object(a.object)
	s, err := newGCSReadSeeker(ctx, handle)
	if err != nil {
		return nil, err
	}

	c, err := lru.New[string, []byte](1024)
	if err != nil {
		return nil, err
	}

	r, err := disk.New(s, c)
	if err != nil {
		return nil, err
	}

	return r, nil
}

func (a *GCS) calcCacheKey() (string, error) {
	key := a.bucket + "/" + a.object
	s, err := cache.CalcKey(key, a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", err
	}
	return s, nil
}

func (a *GCS) hasCache(cacheKey string) bool {
	_, missingCacheKeys, err := a.cache.MissingBlobs(cacheKey, []string{cacheKey})
	if err != nil {
		return false
	}
	if len(missingCacheKeys) == 0 {
		return true
	}
	return false
}

type GCSReadSeeker struct {
	ctx    context.Context
	handle *storage.ObjectHandle
	reader *storage.Reader
	offset int64
	size   int64
}

func newGCSReadSeeker(ctx context.Context, handle *storage.ObjectHandle) (*GCSReadSeeker, error) {
	attrs, err := handle.Attrs(ctx)
	if err != nil {
		return nil, err
	}

	return &GCSReadSeeker{
		ctx:    ctx,
		handle: handle,
		reader: nil,
		offset: 0,
		size:   attrs.Size,
	}, nil
}

func (a *GCSReadSeeker) Read(p []byte) (int, error) {
	var err error

	if a.reader == nil {
		a.reader, err = a.handle.NewRangeReader(a.ctx, a.offset, int64(len(p)))
		if err != nil {
			return 0, err
		}
	}

	n, err := a.reader.Read(p)
	if err != nil {
		return 0, err
	}

	return n, nil
}

func (a *GCSReadSeeker) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64

	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = a.offset + offset
	case io.SeekEnd:
		newOffset = a.size - offset
	}

	if a.reader != nil {
		a.reader.Close()
		a.reader = nil
	}

	a.offset = newOffset
	return a.offset, nil
}
