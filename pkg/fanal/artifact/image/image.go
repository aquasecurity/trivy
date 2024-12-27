package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"

	"github.com/cheggaaa/pb/v3"
	"github.com/docker/go-units"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/partial"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/parallel"
	"github.com/aquasecurity/trivy/pkg/semaphore"
	trivyTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Artifact struct {
	logger         *log.Logger
	image          types.Image
	cache          cache.ArtifactCache
	walker         walker.LayerTar
	analyzer       analyzer.AnalyzerGroup       // analyzer for files in container image
	configAnalyzer analyzer.ConfigAnalyzerGroup // analyzer for container image config
	handlerManager handler.Manager

	artifactOption artifact.Option

	cacheDir string
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

	a, err := analyzer.NewAnalyzerGroup(opt.AnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("analyzer group error: %w", err)
	}

	ca, err := analyzer.NewConfigAnalyzerGroup(opt.ConfigAnalyzerOptions())
	if err != nil {
		return nil, xerrors.Errorf("config analyzer group error: %w", err)
	}

	cacheDir, err := os.MkdirTemp("", "layers")
	if err != nil {
		return nil, xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	return Artifact{
		logger:         log.WithPrefix("image"),
		image:          img,
		cache:          c,
		walker:         walker.NewLayerTar(opt.WalkerOption),
		analyzer:       a,
		configAnalyzer: ca,
		handlerManager: handlerManager,

		artifactOption: opt,
		cacheDir:       cacheDir,
	}, nil
}

func (a Artifact) Inspect(ctx context.Context) (artifact.Reference, error) {
	imageID, err := a.image.ID()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image ID: %w", err)
	}
	a.logger.Debug("Detected image ID", log.String("image_id", imageID))

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	diffIDs := a.diffIDs(configFile)
	a.logger.Debug("Detected diff ID", log.Any("diff_ids", diffIDs))

	defer os.RemoveAll(a.cacheDir)
	if err := a.checkImageSize(ctx); err != nil {
		return artifact.Reference{}, err
	}

	// Try retrieving a remote SBOM document
	if res, err := a.retrieveRemoteSBOM(ctx); err == nil {
		// Found SBOM
		return res, nil
	} else if !errors.Is(err, errNoSBOMFound) {
		// Fail on unexpected error, otherwise it falls into the usual scanning.
		return artifact.Reference{}, xerrors.Errorf("remote SBOM fetching error: %w", err)
	}

	// Try to detect base layers.
	baseDiffIDs := a.guessBaseLayers(diffIDs, configFile)
	a.logger.Debug("Detected base layers", log.Any("diff_ids", baseDiffIDs))

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return artifact.Reference{}, err
	}

	// Parse histories and extract a list of "created_by"
	layerKeyMap := a.consolidateCreatedBy(diffIDs, layerKeys, configFile)

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return artifact.Reference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		a.logger.Debug("Missing image ID in cache", log.String("image_id", imageID))
	} else {
		missingImageKey = ""
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, baseDiffIDs, layerKeyMap, configFile); err != nil {
		return artifact.Reference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return artifact.Reference{
		Name:    a.image.Name(),
		Type:    artifact.TypeContainerImage,
		ID:      imageKey,
		BlobIDs: layerKeys,
		ImageMetadata: artifact.ImageMetadata{
			ID:          imageID,
			DiffIDs:     diffIDs,
			RepoTags:    a.image.RepoTags(),
			RepoDigests: a.image.RepoDigests(),
			ConfigFile:  *configFile,
		},
	}, nil
}

func (Artifact) Clean(_ artifact.Reference) error {
	return nil
}

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, error) {
	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.configAnalyzer.AnalyzerVersions(), nil, artifact.Option{})
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

	layerKeyMap := make(map[string]LayerInfo)
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

func (a Artifact) checkImageSize(ctx context.Context) error {
	maxSize := a.artifactOption.ImageOption.MaxImageSize
	if maxSize == 0 {
		return nil
	}

	imageSize, err := a.downloadImage(ctx)
	if err != nil {
		return xerrors.Errorf("failed to calculate image size: %w", err)
	}

	if imageSize > maxSize {
		return &trivyTypes.UserError{
			Message: fmt.Sprintf(
				"uncompressed image size %s exceeds maximum allowed size %s",
				units.HumanSizeWithPrecision(float64(imageSize), 3),
				units.HumanSize(float64(maxSize)),
			),
		}
	}
	return nil
}

// progressLayer wraps a v1.Layer to add progress bar functionality
type progressLayer struct {
	v1.Layer
	bar *pb.ProgressBar
}

func newProgressLayer(layer v1.Layer, bar *pb.ProgressBar) (v1.Layer, error) {
	return partial.CompressedToLayer(&progressLayer{
		Layer: layer, bar: bar,
	})
}

func (l *progressLayer) Compressed() (io.ReadCloser, error) {
	rc, err := l.Layer.Compressed()
	if err != nil {
		return nil, err
	}

	return l.bar.NewProxyReader(rc), nil
}

func (a Artifact) downloadImage(ctx context.Context) (int64, error) {
	layers, err := a.image.Layers()
	if err != nil {
		return -1, xerrors.Errorf("failed to get image layers: %w", err)
	}

	if !a.artifactOption.NoProgress {
		progressPool := pb.NewPool()
		wrappedLayers, err := a.wrapLayers(layers, progressPool)
		if err != nil {
			return -1, xerrors.Errorf("failed to wrap")
		}
		if err := progressPool.Start(); err != nil {
			log.Error("Failed to start progress bar pool", log.Err(err))
		} else {
			defer progressPool.Stop()
			layers = wrappedLayers
		}

	}

	var imageSize int64
	p := parallel.NewPipeline(a.artifactOption.Parallel, false, layers,
		func(ctx context.Context, layer v1.Layer) (int64, error) {
			layerSize, err := a.downloadLayer(layer)
			if err != nil {
				return -1, xerrors.Errorf("failed to save layer: %w", err)
			}
			return layerSize, nil
		},
		func(layerSize int64) error {
			imageSize += layerSize
			return nil
		},
	)

	if err := p.Do(ctx); err != nil {
		return -1, xerrors.Errorf("pipeline error: %w", err)
	}

	return imageSize, nil
}

func (a Artifact) wrapLayers(layers []v1.Layer, progressPool *pb.Pool) ([]v1.Layer, error) {
	wrappedLayers := make([]v1.Layer, 0, len(layers))
	for _, l := range layers {
		size, err := l.Size()
		if err != nil {
			return nil, err
		}
		bar := pb.New64(size).SetTemplate(pb.Full)
		progressPool.Add(bar)
		pl, err := newProgressLayer(l, bar)
		if err != nil {
			return nil, xerrors.Errorf("failed to create progress layer: %w", err)
		}
		wrappedLayers = append(wrappedLayers, pl)
	}
	return wrappedLayers, nil
}

func (a Artifact) downloadLayer(layer v1.Layer) (int64, error) {
	rc, err := layer.Compressed()
	if err != nil {
		return -1, xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	h, err := layer.DiffID()
	if err != nil {
		return -1, xerrors.Errorf("failed to get hash of layer: %w", err)
	}

	file := filepath.Join(a.cacheDir, h.String())
	f, err := os.Create(file)
	if err != nil {
		return -1, xerrors.Errorf("failed to create a file: %w", err)
	}
	defer f.Close()

	dr, err := uncompressed(rc)
	if err != nil {
		return -1, xerrors.Errorf("failed to init decompressor: %w", err)
	}
	defer dr.Close()

	n, err := io.Copy(f, dr)
	if err != nil {
		return -1, xerrors.Errorf("failed to download layer: %w", err)
	}

	return n, nil
}

func (a Artifact) inspect(ctx context.Context, missingImage string, layerKeys, baseDiffIDs []string,
	layerKeyMap map[string]LayerInfo, configFile *v1.ConfigFile) error {

	var osFound types.OS
	p := parallel.NewPipeline(a.artifactOption.Parallel, false, layerKeys, func(ctx context.Context,
		layerKey string) (any, error) {
		layer := layerKeyMap[layerKey]

		// If it is a base layer, secret scanning should not be performed.
		var disabledAnalyzers []analyzer.Type
		if slices.Contains(baseDiffIDs, layer.DiffID) {
			disabledAnalyzers = append(disabledAnalyzers, analyzer.TypeSecret)
		}

		layerInfo, err := a.inspectLayer(ctx, layer, disabledAnalyzers)
		if err != nil {
			return nil, xerrors.Errorf("failed to analyze layer (%s): %w", layer.DiffID, err)
		}
		if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
			return nil, xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
		}
		if lo.IsNotEmpty(layerInfo.OS) {
			osFound = layerInfo.OS
		}
		return nil, nil

	}, nil)

	if err := p.Do(ctx); err != nil {
		return xerrors.Errorf("pipeline error: %w", err)
	}

	if missingImage != "" {
		if err := a.inspectConfig(ctx, missingImage, osFound, configFile); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil
}

func (a Artifact) inspectLayer(ctx context.Context, layerInfo LayerInfo, disabled []analyzer.Type) (types.BlobInfo, error) {
	a.logger.Debug("Missing diff ID in cache", log.String("diff_id", layerInfo.DiffID))

	layerDigest, rc, err := a.uncompressedLayer(layerInfo.DiffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", layerInfo.DiffID, err)
	}
	defer rc.Close()

	// Prepare variables
	var wg sync.WaitGroup
	opts := analyzer.AnalysisOptions{
		Offline:      a.artifactOption.Offline,
		FileChecksum: a.artifactOption.FileChecksum,
	}
	result := analyzer.NewAnalysisResult()
	limit := semaphore.New(a.artifactOption.Parallel)

	// Prepare filesystem for post analysis
	composite, err := a.analyzer.PostAnalyzerFS()
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get post analysis filesystem: %w", err)
	}
	defer composite.Cleanup()

	// Walk a tar layer
	opqDirs, whFiles, err := a.walker.Walk(rc, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener, disabled, opts); err != nil {
			return xerrors.Errorf("failed to analyze %s: %w", filePath, err)
		}

		// Skip post analysis if the file is not required
		analyzerTypes := a.analyzer.RequiredPostAnalyzers(filePath, info)
		if len(analyzerTypes) == 0 {
			return nil
		}

		// Build filesystem for post analysis
		tmpFilePath, err := composite.CopyFileToTemp(opener, info)
		if err != nil {
			return xerrors.Errorf("failed to copy file to temp: %w", err)
		}
		if err = composite.CreateLink(analyzerTypes, "", filePath, tmpFilePath); err != nil {
			return xerrors.Errorf("failed to write a file: %w", err)
		}

		return nil
	})
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("walk error: %w", err)
	}

	// Wait for all the goroutine to finish.
	wg.Wait()

	// Post-analysis
	if err = a.analyzer.PostAnalyze(ctx, composite, result, opts); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("post analysis error: %w", err)
	}

	// Sort the analysis result for consistent results
	result.Sort()

	blobInfo := types.BlobInfo{
		SchemaVersion:     types.BlobJSONSchemaVersion,
		Digest:            layerDigest,
		DiffID:            layerInfo.DiffID,
		CreatedBy:         layerInfo.CreatedBy,
		OpaqueDirs:        opqDirs,
		WhiteoutFiles:     whFiles,
		OS:                result.OS,
		Repository:        result.Repository,
		PackageInfos:      result.PackageInfos,
		Applications:      result.Applications,
		Misconfigurations: result.Misconfigurations,
		Secrets:           result.Secrets,
		Licenses:          result.Licenses,
		CustomResources:   result.CustomResources,

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

func (a Artifact) uncompressedLayer(diffID string) (string, io.ReadCloser, error) {
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

	f, err := os.Open(filepath.Join(a.cacheDir, diffID))
	if err == nil {
		return digest, f, nil
	}

	rc, err := layer.Uncompressed()
	if err != nil {
		return "", nil, xerrors.Errorf("failed to get the layer content (%s): %w", diffID, err)
	}
	return digest, rc, nil
}

// ref. https://github.com/google/go-containerregistry/issues/701
func (a Artifact) isCompressed(l v1.Layer) bool {
	_, uncompressed := reflect.TypeOf(l).Elem().FieldByName("UncompressedLayer")
	return !uncompressed
}

func (a Artifact) inspectConfig(ctx context.Context, imageID string, osFound types.OS, config *v1.ConfigFile) error {
	result := lo.FromPtr(a.configAnalyzer.AnalyzeImageConfig(ctx, osFound, config))

	info := types.ArtifactInfo{
		SchemaVersion:    types.ArtifactJSONSchemaVersion,
		Architecture:     config.Architecture,
		Created:          config.Created.Time,
		DockerVersion:    config.DockerVersion,
		OS:               config.OS,
		Misconfiguration: result.Misconfiguration,
		Secret:           result.Secret,
		HistoryPackages:  result.HistoryPackages,
	}

	if err := a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

// guessBaseLayers guesses layers in base image (call base layers).
func (a Artifact) guessBaseLayers(diffIDs []string, configFile *v1.ConfigFile) []string {
	if configFile == nil {
		return nil
	}

	baseImageIndex := image.GuessBaseImageIndex(configFile.History)

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
