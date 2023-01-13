package image

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/semaphore"
)

type Artifact struct {
	image          types.Image
	cache          cache.ArtifactCache
	walker         walker.LayerTar
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption artifact.Option
}

type LayerInfo struct {
	DiffID    string
	CreatedBy string // can be empty
}

func NewArtifact(img types.Image, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	// Initialize handlers
	handlerManager, err := handler.NewManager(opt)
	if err != nil {
		return nil, xerrors.Errorf("handler init error: %w", err)
	}

	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                opt.AnalyzerGroup,
		FilePatterns:         opt.FilePatterns,
		DisabledAnalyzers:    opt.DisabledAnalyzers,
		SecretScannerOption:  opt.SecretScannerOption,
		LicenseScannerOption: opt.LicenseScannerOption,
	})
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	return Artifact{
		image:          img,
		cache:          c,
		walker:         walker.NewLayerTar(opt.SkipFiles, opt.SkipDirs, opt.OnlyDirs, opt.Slow),
		analyzer:       a,
		handlerManager: handlerManager,

		artifactOption: opt,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (types.ArtifactReference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	diffIDs := a.diffIDs(configFile)

	// Debug
	log.Logger.Debugf("Image ID: %s", imageID)
	log.Logger.Debugf("Diff IDs: %v", diffIDs)

	// Try retrieving a remote SBOM document
	if res, err := a.retrieveRemoteSBOM(ctx); err == nil {
		// Found SBOM
		return res, nil
	} else if !errors.Is(err, errNoSBOMFound) {
		// Fail on unexpected error, otherwise it falls into the usual scanning.
		return types.ArtifactReference{}, xerrors.Errorf("remote SBOM fetching error: %w", err)
	}

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	log.Logger.Debugf("Base Layers: %v", baseDiffIDs)

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, err
	}

	// Parse histories and extract a list of "created_by"
	layerKeyMap := a.consolidateCreatedBy(diffIDs, layerKeys, configFile)

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		log.Logger.Debugf("Missing image ID in cache: %s", imageID)
	} else {
		missingImageKey = ""
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, baseDiffIDs, layerKeyMap); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ArtifactReference{
		Name:    a.image.Name(),
		Type:    types.ArtifactContainerImage,
		ID:      imageKey,
		BlobIDs: layerKeys,
		ImageMetadata: types.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.image.RepoTags(),
			RepoDigests: a.image.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (Artifact) Clean(_ types.ArtifactReference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.ImageConfigAnalyzerVersions(), nil, artifact.Option{})
	if err != nil {
		return "", nil, err
	}

	hookVersions := a.handlerManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), hookVersions, a.artifactOption)
		if err != nil {
			return "", nil, err
		}
		layerKeys = append(layerKeys, blobKey)
	}
	return imageKey, layerKeys, nil
}

func (a Artifact) consolidateCreatedBy(diffIDs, layerKeys []string, configFile *v1.ConfigFile) map[string]LayerInfo {
	// save createdBy fields in order of layers
	var createdBy []string
	for _, h := range configFile.History {
		// skip histories for empty layers
		if h.EmptyLayer {
			continue
		}
		c := strings.TrimPrefix(h.CreatedBy, "/bin/sh -c ")
		c = strings.TrimPrefix(c, "#(nop) ")
		createdBy = append(createdBy, c)
	}

	// If history detected incorrect - use only diffID
	// TODO: our current logic may not detect empty layers correctly in rare cases.
	validCreatedBy := len(diffIDs) == len(createdBy)

	layerKeyMap := map[string]LayerInfo{}
	for i, diffID := range diffIDs {

		c := ""
		if validCreatedBy {
			c = createdBy[i]
		}

		layerKey := layerKeys[i]
		layerKeyMap[layerKey] = LayerInfo{
			DiffID:    diffID,
			CreatedBy: c,
		}
	}
	return layerKeyMap
}

func (a Artifact) inspect(ctx context.Context, missingImage string, layerKeys, baseDiffIDs []string, layerKeyMap map[string]LayerInfo) error {
	done := make(chan struct{}, len(layerKeys))
	errCh := make(chan error, len(layerKeys))
	limit := semaphore.New(a.artifactOption.Slow)

	var osFound types.OS
	for _, k := range layerKeys {
		if err := limit.Acquire(ctx, 1); err != nil {
			return xerrors.Errorf("semaphore acquire: %w", err)
		}

		go func(ctx context.Context, layerKey string) {
			defer func() {
				limit.Release(1)
				done <- struct{}{}
			}()

			layer := layerKeyMap[layerKey]

			// If it is a base layer, secret scanning should not be performed.
			var disabledAnalyers []analyzer.Type
			if slices.Contains(baseDiffIDs, layer.DiffID) {
				disabledAnalyers = append(disabledAnalyers, analyzer.TypeSecret)
			}

			layerInfo, err := a.inspectLayer(ctx, layer, disabledAnalyers)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", layerInfo.DiffID, err)
				return
			}
			if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
				return
			}
			if lo.IsNotEmpty(layerInfo.OS) {
				osFound = layerInfo.OS
			}
		}(ctx, k)
	}

	for range layerKeys {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}

	if missingImage != "" {
		if err := a.inspectConfig(missingImage, osFound); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil
}

func (a Artifact) inspectLayer(ctx context.Context, layerInfo LayerInfo, disabled []analyzer.Type) (types.BlobInfo, error) {
	log.Logger.Debugf("Missing diff ID in cache: %s", layerInfo.DiffID)

	layerDigest, r, err := a.uncompressedLayer(layerInfo.DiffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", layerInfo.DiffID, err)
	}

	// Prepare variables
	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{Offline: a.artifactOption.Offline}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Slow)

	// Walk a tar layer
	opqDirs, whFiles, err := a.walker.Walk(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}
		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:   types.BlobJSONSchemaVersion,
		Digest:          layerDigest,
		DiffID:          layerInfo.DiffID,
		CreatedBy:       layerInfo.CreatedBy,
		OpaqueDirs:      opqDirs,
		WhiteoutFiles:   whFiles,
		OS:              result.OS,
		Repository:      result.Repository,
		PackageInfos:    result.PackageInfos,
		Applications:    result.Applications,
		Secrets:         result.Secrets,
		Licenses:        result.Licenses,
		CustomResources: result.CustomResources,

		// For Red Hat
		BuildInfo: result.BuildInfo,
	}

	// Call post handlers to modify blob info
	if err = a.handlerManager.PostHandle(ctx, result, &blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post handler error: %w", err)
	}

	return blobInfo, nil
}

func (a Artifact) diffIDs(configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}
	return lo.Map(configFile.RootFS.DiffIDs, func(diffID v1.Hash, _ int) string {
		return diffID.String()
	})
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
	config, err := a.image.ConfigFile()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	result := lo.FromPtr(a.analyzer.AnalyzeImageConfig(osFound, config))

	// Identify packages from history.
	var historyPkgs types.Packages
	for _, pi := range result.PackageInfos {
		if pi.FilePath == types.HistoryPkgs {
			historyPkgs = pi.Packages
			break
		}
	}

	info := types.ArtifactInfo{
		SchemaVersion:   types.ArtifactJSONSchemaVersion,
		Architecture:    config.Architecture,
		Created:         config.Created.Time,
		DockerVersion:   config.DockerVersion,
		OS:              config.OS,
		HistoryPackages: historyPkgs,
	}

	if err = a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

// Guess layers in base image (call base layers).
//
// e.g. In the following example, we should detect layers in debian:8.
//
//	FROM debian:8
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"]
//	CMD ["somecmd"]
//
// debian:8 may be like
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]
//
// In total, it would be like:
//
//	ADD file:5d673d25da3a14ce1f6cf66e4c7fd4f4b85a3759a9d93efb3fd9ff852b5b56e4 in /
//	CMD ["/bin/sh"]              # empty layer (detected)
//	RUN apt-get update
//	COPY mysecret /
//	ENTRYPOINT ["entrypoint.sh"] # empty layer (skipped)
//	CMD ["somecmd"]              # empty layer (skipped)
//
// This method tries to detect CMD in the second line and assume the first line is a base layer.
//  1. Iterate histories from the bottom.
//  2. Skip all the empty layers at the bottom. In the above example, "entrypoint.sh" and "somecmd" will be skipped
//  3. If it finds CMD, it assumes that it is the end of base layers.
//  4. It gets all the layers as base layers above the CMD found in #3.
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	baseImageIndex := -1
	var foundNonEmpty bool
	for i := len(configFile.History) - 1; i >= 0; i-- {
		h := configFile.History[i]

		// Skip the last CMD, ENTRYPOINT, etc.
		if !foundNonEmpty {
			if h.EmptyLayer {
				continue
			}
			foundNonEmpty = true
		}

		if !h.EmptyLayer {
			continue
		}

		// Detect CMD instruction in base image
		if strings.HasPrefix(h.CreatedBy, "/bin/sh -c #(nop)  CMD") ||
			strings.HasPrefix(h.CreatedBy, "CMD") { // BuildKit
			baseImageIndex = i
			break
		}
	}

	// Diff IDs don't include empty layers, so the index is different from histories
	var diffIDIndex int
	var baseDiffIDs []string
	for i, h := range configFile.History {
		// It is no longer base layer.
		if i > baseImageIndex {
			break
		}
		// Empty layers are not included in diff IDs.
		if h.EmptyLayer {
			continue
		}

		if diffIDIndex >= len(diffIDs) {
			// something wrong...
			return nil
		}
		baseDiffIDs = append(baseDiffIDs, diffIDs[diffIDIndex])
		diffIDIndex++
	}
	return baseDiffIDs
}
