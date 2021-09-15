package image

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"golang.org/x/sync/semaphore"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/artifact"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/config/scanner"
	"github.com/aquasecurity/fanal/hook"
	"github.com/aquasecurity/fanal/log"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/walker"
)

const (
	parallel = 5
)

var (
	defaultDisabledAnalyzers = []analyzer.Type{
		// Do not scan go.sum in container images, only scan go binaries
		analyzer.TypeGoMod,

		// Do not scan requirements.txt, Pipfile.lock and poetry.lock in container images, only scan egg and wheel
		analyzer.TypePip,
		analyzer.TypePipenv,
		analyzer.TypePoetry,

		// Do not scan Gemfile.lock in container images, only scan .gemspec
		analyzer.TypeBundler,

		// Do not scan package-lock.json and yarn.lock in container images, only scan package.json
		analyzer.TypeNpmPkgLock,
		analyzer.TypeYarn,
	}

	defaultDisabledHooks []hook.Type
)

type Artifact struct {
	image               types.Image
	cache               cache.ArtifactCache
	analyzer            analyzer.Analyzer
	hookManager         hook.Manager
	scanner             scanner.Scanner
	configScannerOption config.ScannerOption
}

func NewArtifact(img types.Image, c cache.ArtifactCache, disabledAnalyzers []analyzer.Type, disabledHooks []hook.Type,
	opt config.ScannerOption) (artifact.Artifact, error) {
	// Register config analyzers
	if err := config.RegisterConfigAnalyzers(opt.FilePatterns); err != nil {
		return nil, xerrors.Errorf("config scanner error: %w", err)
	}

	s, err := scanner.New("", opt.Namespaces, opt.PolicyPaths, opt.DataPaths, opt.Trace)
	if err != nil {
		return nil, xerrors.Errorf("scanner error: %w", err)
	}

	disabledAnalyzers = append(disabledAnalyzers, defaultDisabledAnalyzers...)
	disabledHooks = append(disabledHooks, defaultDisabledHooks...)

	return Artifact{
		image:               img,
		cache:               c,
		analyzer:            analyzer.NewAnalyzer(disabledAnalyzers),
		hookManager:         hook.NewManager(disabledHooks),
		scanner:             s,
		configScannerOption: opt,
	}, nil
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

	configFile, err := a.image.ConfigFile()
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get the image's config file: %w", err)
	}

	// Debug
	log.Logger.Debugf("Image ID: %s", imageID)
	log.Logger.Debugf("Diff IDs: %v", diffIDs)

	// Convert image ID and layer IDs to cache keys
	imageKey, layerKeys, layerKeyMap, err := a.calcCacheKeys(imageID, diffIDs)
	if err != nil {
		return types.ArtifactReference{}, err
	}

	missingImage, missingLayers, err := a.cache.MissingBlobs(imageKey, layerKeys)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	missingImageKey := imageKey
	if missingImage {
		log.Logger.Debugf("Missing image ID: %s", imageID)
	} else {
		missingImageKey = ""
	}

	if err = a.inspect(ctx, missingImageKey, missingLayers, layerKeyMap); err != nil {
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

func (a Artifact) calcCacheKeys(imageID string, diffIDs []string) (string, []string, map[string]string, error) {

	// Pass an empty config scanner option so that the cache key can be the same, even when policies are updated.
	imageKey, err := cache.CalcKey(imageID, a.analyzer.ImageConfigAnalyzerVersions(), nil, &config.ScannerOption{})
	if err != nil {
		return "", nil, nil, err
	}

	layerKeyMap := map[string]string{}
	hookVersions := a.hookManager.Versions()
	var layerKeys []string
	for _, diffID := range diffIDs {
		blobKey, err := cache.CalcKey(diffID, a.analyzer.AnalyzerVersions(), hookVersions, &a.configScannerOption)
		if err != nil {
			return "", nil, nil, err
		}
		layerKeys = append(layerKeys, blobKey)
		layerKeyMap[blobKey] = diffID
	}
	return imageKey, layerKeys, layerKeyMap, nil
}

func (a Artifact) inspect(ctx context.Context, missingImage string, layerKeys []string, layerKeyMap map[string]string) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, k := range layerKeys {
		go func(ctx context.Context, layerKey string) {
			diffID := layerKeyMap[layerKey]
			layerInfo, err := a.inspectLayer(ctx, diffID)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", diffID, err)
				return
			}
			if err = a.cache.PutBlob(layerKey, layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", layerKey, err)
				return
			}
			if layerInfo.OS != nil {
				osFound = *layerInfo.OS
			}
			done <- struct{}{}
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
		log.Logger.Debugf("Missing image cache: %s", missingImage)
		if err := a.inspectConfig(missingImage, osFound); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil

}

func (a Artifact) inspectLayer(ctx context.Context, diffID string) (types.BlobInfo, error) {
	log.Logger.Debugf("Missing diff ID: %s", diffID)

	layerDigest, r, err := a.uncompressedLayer(diffID)
	if err != nil {
		return types.BlobInfo{}, xerrors.Errorf("unable to get uncompressed layer %s: %w", diffID, err)
	}

	var wg sync.WaitGroup
	result := new(analyzer.AnalysisResult)
	limit := semaphore.NewWeighted(parallel)

	opqDirs, whFiles, err := walker.WalkLayerTar(r, func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
		if err = a.analyzer.AnalyzeFile(ctx, &wg, limit, result, "", filePath, info, opener); err != nil {
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
		SchemaVersion: types.BlobJSONSchemaVersion,
		Digest:        layerDigest,
		DiffID:        diffID,
		OS:            result.OS,
		PackageInfos:  result.PackageInfos,
		Applications:  result.Applications,
		SystemFiles:   result.SystemInstalledFiles,
		OpaqueDirs:    opqDirs,
		WhiteoutFiles: whFiles,
	}

	// Call hooks to modify blob info
	if err = a.hookManager.CallHooks(&blobInfo); err != nil {
		return types.BlobInfo{}, xerrors.Errorf("failed to call hooks: %w", err)
	}

	return blobInfo, nil
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
	configBlob, err := a.image.RawConfigFile()
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	pkgs := a.analyzer.AnalyzeImageConfig(osFound, configBlob)

	var s1 v1.ConfigFile
	if err = json.Unmarshal(configBlob, &s1); err != nil {
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

	if err = a.cache.PutArtifact(imageID, info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}
