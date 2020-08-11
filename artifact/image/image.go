package image

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

type Artifact struct {
	image image.Image
	cache cache.ArtifactCache
}

func NewArtifact(img image.Image, c cache.ArtifactCache) artifact.Artifact {
	return Artifact{
		image: img,
		cache: c,
	}
}

func (a Artifact) Inspect(ctx context.Context, option artifact.InspectOption) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get layer IDs: %w", err)
	}

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	if err := a.inspect(ctx, imageID, missingImage, missingLayers, option); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ArtifactReference{
		Name:    a.image.Name(),
		ID:      imageID,
		BlobIDs: diffIDs,
	}, nil

}

func (a Artifact) inspect(ctx context.Context, imageID string, missingImage bool, diffIDs []string, option artifact.InspectOption) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, d := range diffIDs {
		go func(diffID string) {
			layerInfo, err := a.inspectLayer(diffID, option)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			if err = a.cache.PutBlob(diffID, layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", diffID, err)
				return
			}
			if layerInfo.OS != nil {
				osFound = *layerInfo.OS
			}
			done <- struct{}{}
		}(d)
	}

	for range diffIDs {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}

	if missingImage {
		if err := a.inspectConfig(imageID, osFound); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil

}

func (a Artifact) inspectLayer(diffID string, option artifact.InspectOption) (types.BlobInfo, error) {
	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	result := new(analyzer.AnalysisResult)
	opqDirs, whFiles, err := walker.WalkLayerTar(r, option.SkipDirectories, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		r, err := analyzer.AnalyzeFile(filePath, info, opener)
		if err != nil {
			return err
		}
		result.Merge(r)
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, err
	}

	layerInfo := types.BlobInfo{
		Digest:        layerDigest,
		DiffID:        diffID,
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		OpaqueDirs:    opqDirs,
		WhiteoutFiles: whFiles,
	}
	return layerInfo, nil
}

func (a Artifact) uncompressedLayer(diffID string) (string, io.Reader, error) {
	// diffID is a hash of the uncompressed layer
	h, err := v1.NewHash(diffID)
	if err != nil {
		return "", nil, xerrors.Errorf("invalid layer ID (%s): %w", diffID, err)
	}

	layer, err := a.image.LayerByDiffID(h)
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer (%s): %w", diffID, err)
	}

	// digest is a hash of the compressed layer
	var digest string
	if a.isCompressed(layer) {
		d, err := layer.Digest()
		if err != nil {
			return "", nil, xerrors.Errorf("failed to get the digest (%s): %w", diffID, err)
		}
		digest = d.String()
	}

	r, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, r, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(imageID string, osFound types.OS) error {
	configBlob, err := a.image.ConfigBlob()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	pkgs := analyzer.AnalyzeConfig(osFound, configBlob)

	var s1 v1.ConfigFile
	if err := json.Unmarshal(configBlob, &s1); err != nil {
		return xerrors.Errorf("json marshal error: %w", err)
	}

	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    s1.Architecture,
		Created:         s1.Created.Time,
		DockerVersion:   s1.DockerVersion,
		OS:              s1.OS,
		HistoryPackages: pkgs,
	}

	if err := a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}
