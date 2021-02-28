package image

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"

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
	image    image.Image
	cache    cache.ArtifactCache
	analyzer analyzer.Analyzer
}

func NewArtifact(img image.Image, c cache.ArtifactCache, disabled []analyzer.Type) artifact.Artifact {
	return Artifact{
		image:    img,
		cache:    c,
		analyzer: analyzer.NewAnalyzer(disabled),
	}
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	diffIDs, err := a.image.LayerIDs()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get layer IDs: %w", err)
	}

	versionedImageID, versionedDiffIDs := a.withVersionSuffix(imageID, diffIDs)

	missingImage, missingLayers, err := a.cache.MissingBlobs(versionedImageID, versionedDiffIDs)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	if err := a.inspect(ctx, versionedImageID, missingImage, missingLayers); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ArtifactReference{
		Name:        a.image.Name(),
		ID:          versionedImageID,
		BlobIDs:     versionedDiffIDs,
		RepoTags:    a.image.RepoTags(),
		RepoDigests: a.image.RepoDigests(),
	}, nil

}

func (a Artifact) withVersionSuffix(imageID string, diffIDs []string) (string, []string) {
	// e.g. sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e
	//   => sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e/1
	imageID = cache.WithVersionSuffix(imageID, a.analyzer.ImageConfigAnalyzerVersions())

	var blobIDs []string
	for _, diffID := range diffIDs {
		// e.g. sha256:0fcbbeeeb0d7fc5c06362d7a6717b999e605574c7210eff4f7418f6e9be9fbfe
		//   => sha256:0fcbbeeeb0d7fc5c06362d7a6717b999e605574c7210eff4f7418f6e9be9fbfe/121110111321
		blobID := cache.WithVersionSuffix(diffID, a.analyzer.AnalyzerVersions())
		blobIDs = append(blobIDs, blobID)
	}
	return imageID, blobIDs
}

func (a Artifact) inspect(ctx context.Context, imageID string, missingImage bool, diffIDs []string) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, d := range diffIDs {
		go func(versionedDiffID string) {
			diffID := cache.TrimVersionSuffix(versionedDiffID)
			layerInfo, err := a.inspectLayer(diffID)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			if err = a.cache.PutBlob(versionedDiffID, layerInfo); err != nil {
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

func (a Artifact) inspectLayer(diffID string) (types.BlobInfo, error) {
	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)

	opqDirs, whFiles, err := walker.WalkLayerTar(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(&wg, result, filePath, info, opener); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	result.Sort()

	layerInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		Digest:        layerDigest,
		DiffID:        diffID,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		Configs:       result.Configs,
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

	pkgs := a.analyzer.AnalyzeImageConfig(osFound, configBlob)

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
