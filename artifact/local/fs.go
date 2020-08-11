package local

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

type Artifact struct {
	dir   string
	cache cache.ArtifactCache
}

func NewArtifact(dir string, c cache.ArtifactCache) artifact.Artifact {
	return Artifact{
		dir:   dir,
		cache: c,
	}
}

func (a Artifact) Inspect(_ context.Context, option artifact.InspectOption) (types.ArtifactReference, error) {
	var result analyzer.AnalysisResult
	err := walker.WalkDir(a.dir, option.SkipDirectories, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		filePath, err := filepath.Rel(a.dir, filePath)
		if err != nil {
			return err
		}
		r, err := analyzer.AnalyzeFile(filePath, info, opener)
		if err != nil {
			return err
		}
		result.Merge(r)
		return nil
	})
	if err != nil {
		return types.ArtifactReference{}, err
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
	}

	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err = json.NewEncoder(h).Encode(blobInfo); err != nil {
		return types.ArtifactReference{}, err
	}

	d := digest.NewDigest(digest.SHA256, h)
	diffID := d.String()
	blobInfo.DiffID = diffID

	if err = a.cache.PutBlob(diffID, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", diffID, err)
	}

	// get hostname
	var hostName string
	b, err := ioutil.ReadFile(filepath.Join(a.dir, "etc", "hostname"))
	if err == nil && string(b) != "" {
		hostName = strings.TrimSpace(string(b))
	} else {
		hostName = a.dir
	}

	return types.ArtifactReference{
		Name:    hostName,
		ID:      diffID, // use diffID as pseudo artifactID
		BlobIDs: []string{diffID},
	}, nil
}
