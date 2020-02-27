package analyzer

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/aquasecurity/fanal/extractor/docker"
	"github.com/containers/image/v5/manifest"
	digest "github.com/opencontainers/go-digest"

	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/types"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/extractor"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	osAnalyzers      []OSAnalyzer
	pkgAnalyzers     []PkgAnalyzer
	libAnalyzers     []LibraryAnalyzer
	commandAnalyzers []CommandAnalyzer
	additionalFiles  []string

	// ErrUnknownOS occurs when unknown OS is analyzed.
	ErrUnknownOS = xerrors.New("unknown OS")
	// ErrPkgAnalysis occurs when the analysis of packages is failed.
	ErrPkgAnalysis = xerrors.New("failed to analyze packages")
	// ErrNoPkgsDetected occurs when the required files for an OS package manager are not detected
	ErrNoPkgsDetected = xerrors.New("no packages detected")
)

type OSAnalyzer interface {
	Analyze(extractor.FileMap) (types.OS, error)
	RequiredFiles() []string
}

type PkgAnalyzer interface {
	Analyze(extractor.FileMap) (map[types.FilePath][]types.Package, error)
	RequiredFiles() []string
}

type CommandAnalyzer interface {
	Analyze(types.OS, extractor.FileMap) ([]types.Package, error)
	RequiredFiles() []string
}

type LibraryAnalyzer interface {
	Name() string
	Analyze(extractor.FileMap) (map[types.FilePath][]godeptypes.Library, error)
	RequiredFiles() []string
}

func RegisterOSAnalyzer(analyzer OSAnalyzer) {
	osAnalyzers = append(osAnalyzers, analyzer)
}

func RegisterPkgAnalyzer(analyzer PkgAnalyzer) {
	pkgAnalyzers = append(pkgAnalyzers, analyzer)
}

func RegisterCommandAnalyzer(analyzer CommandAnalyzer) {
	commandAnalyzers = append(commandAnalyzers, analyzer)
}

func RegisterLibraryAnalyzer(analyzer LibraryAnalyzer) {
	libAnalyzers = append(libAnalyzers, analyzer)
}

func AddRequiredFilenames(filenames []string) {
	additionalFiles = append(additionalFiles, filenames...)
}

func RequiredFilenames() []string {
	var filenames []string
	filenames = append(filenames, additionalFiles...)
	for _, analyzer := range osAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range pkgAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	for _, analyzer := range libAnalyzers {
		filenames = append(filenames, analyzer.RequiredFiles()...)
	}
	return filenames
}

type Config struct {
	Extractor extractor.Extractor
	Cache     cache.ImageCache
}

func New(ext extractor.Extractor, c cache.ImageCache) Config {
	return Config{Extractor: ext, Cache: c}
}

func (ac Config) Analyze(ctx context.Context) (types.ImageReference, error) {
	imageID := ac.Extractor.ImageID()
	layerIDs := ac.Extractor.LayerIDs()
	missingImage, missingLayers, err := ac.Cache.MissingLayers(string(imageID), layerIDs)
	if err != nil {
		return types.ImageReference{}, xerrors.Errorf("unable to get missing layers: %w", err)
	}

	if err := ac.analyze(ctx, missingImage, missingLayers); err != nil {
		return types.ImageReference{}, xerrors.Errorf("analyze error: %w", err)
	}

	return types.ImageReference{
		Name:     ac.Extractor.ImageName(),
		ID:       imageID,
		LayerIDs: layerIDs,
	}, nil
}

func (ac Config) analyze(ctx context.Context, missingImage bool, layerIDs []string) error {
	done := make(chan struct{})
	errCh := make(chan error)

	var osFound types.OS
	for _, layerID := range layerIDs {
		go func(dig digest.Digest) {
			decompressedLayerID, layerInfo, err := ac.analyzeLayer(ctx, dig)
			if err != nil {
				errCh <- xerrors.Errorf("failed to analyze layer: %s : %w", dig, err)
				return
			}
			if err = ac.Cache.PutLayer(string(dig), string(decompressedLayerID), layerInfo); err != nil {
				errCh <- xerrors.Errorf("failed to store layer: %s in cache: %w", dig, err)
				return
			}
			if layerInfo.OS != nil {
				osFound = *layerInfo.OS
			}
			done <- struct{}{}
		}(digest.Digest(layerID))
	}

	for range layerIDs {
		select {
		case <-done:
		case err := <-errCh:
			return err
		case <-ctx.Done():
			return xerrors.Errorf("timeout: %w", ctx.Err())
		}
	}

	if missingImage {
		if err := ac.analyzeConfig(ctx, osFound); err != nil {
			return xerrors.Errorf("unable to analyze config: %w", err)
		}
	}

	return nil
}

func (ac Config) analyzeLayer(ctx context.Context, dig digest.Digest) (digest.Digest, types.LayerInfo, error) {
	decompressedLayerID, files, opqDirs, whFiles, err := ac.Extractor.ExtractLayerFiles(ctx, dig, RequiredFilenames())
	if err != nil {
		return "", types.LayerInfo{}, xerrors.Errorf("unable to extract files from layer %s: %w", dig, err)
	}

	os := GetOS(files)
	pkgs, err := GetPackages(files)
	if err != nil {
		return "", types.LayerInfo{}, xerrors.Errorf("failed to get packages: %w", err)
	}
	apps, err := GetLibraries(files)
	if err != nil {
		return "", types.LayerInfo{}, xerrors.Errorf("failed to get libraries: %w", err)
	}

	layerInfo := types.LayerInfo{
		SchemaVersion: types.LayerJSONSchemaVersion,
		OS:            os,
		PackageInfos:  pkgs,
		Applications:  apps,
		OpaqueDirs:    opqDirs,
		WhiteoutFiles: whFiles,
	}
	return decompressedLayerID, layerInfo, nil
}

func (ac Config) analyzeConfig(ctx context.Context, osFound types.OS) error {
	configBlob, err := ac.Extractor.ConfigBlob(ctx)
	if err != nil {
		return xerrors.Errorf("unable to get config blob: %w", err)
	}

	// special file for config
	files := extractor.FileMap{
		"/config": configBlob,
	}
	pkgs, _ := GetPackagesFromCommands(osFound, files)

	var s1 manifest.Schema2V1Image
	if err := json.Unmarshal(configBlob, &s1); err != nil {
		return xerrors.Errorf("json marshal error: %w", err)
	}

	info := types.ImageInfo{
		SchemaVersion:   types.ImageJSONSchemaVersion,
		Architecture:    s1.Architecture,
		Created:         s1.Created,
		DockerVersion:   s1.DockerVersion,
		OS:              s1.OS,
		HistoryPackages: pkgs,
	}

	if err := ac.Cache.PutImage(string(ac.Extractor.ImageID()), info); err != nil {
		return xerrors.Errorf("failed to put image info into the cache: %w", err)
	}

	return nil
}

type Applier struct {
	cache cache.LocalImageCache
}

func NewApplier(c cache.LocalImageCache) Applier {
	return Applier{cache: c}
}

func (a Applier) ApplyLayers(imageID digest.Digest, layerIDs []string) (types.ImageDetail, error) {
	var layers []types.LayerInfo
	for _, layerID := range layerIDs {
		layer, _ := a.cache.GetLayer(layerID)
		if layer.SchemaVersion == 0 {
			return types.ImageDetail{}, xerrors.Errorf("layer cache missing: %s", layerID)
		}
		layers = append(layers, layer)
	}

	mergedLayer := docker.ApplyLayers(layers)
	if mergedLayer.OS == nil {
		return types.ImageDetail{}, ErrUnknownOS
	} else if mergedLayer.Packages == nil {
		return types.ImageDetail{}, ErrNoPkgsDetected
	}

	imageInfo, _ := a.cache.GetImage(string(imageID))
	mergedLayer.HistoryPackages = imageInfo.HistoryPackages

	return mergedLayer, nil
}

func GetOS(filesMap extractor.FileMap) *types.OS {
	for _, analyzer := range osAnalyzers {
		os, err := analyzer.Analyze(filesMap)
		if err != nil {
			continue
		}
		return &os
	}
	return nil
}

func GetPackages(filesMap extractor.FileMap) ([]types.PackageInfo, error) {
	var results []types.PackageInfo
	for _, analyzer := range pkgAnalyzers {
		pkgMap, err := analyzer.Analyze(filesMap)

		// Differentiate between a package manager not being found and another error
		if err != nil && err == ErrNoPkgsDetected {
			continue
		} else if err != nil { // TODO: Create a broken package index tar.gz file
			return nil, xerrors.Errorf("failed to get packages: %w", err)
		}

		for filePath, pkgs := range pkgMap {
			results = append(results, types.PackageInfo{
				FilePath: string(filePath),
				Packages: pkgs,
			})
		}
		// for testability
		sort.Slice(results, func(i, j int) bool {
			return results[i].FilePath < results[j].FilePath
		})
		return results, nil
	}
	return nil, nil
}

// TODO: support this feature
func GetPackagesFromCommands(targetOS types.OS, filesMap extractor.FileMap) ([]types.Package, error) {
	for _, analyzer := range commandAnalyzers {
		pkgs, err := analyzer.Analyze(targetOS, filesMap)
		if err != nil {
			continue
		}
		return pkgs, nil
	}
	return nil, nil
}

func CheckPackage(pkg *types.Package) bool {
	return pkg.Name != "" && pkg.Version != ""
}

func GetLibraries(filesMap extractor.FileMap) ([]types.Application, error) {
	var results []types.Application
	for _, analyzer := range libAnalyzers {
		libMap, err := analyzer.Analyze(filesMap)
		if err != nil {
			return nil, xerrors.Errorf("failed to get libraries: %w", err)
		}

		for filePath, libs := range libMap {
			results = append(results, types.Application{
				Type:      analyzer.Name(),
				FilePath:  string(filePath),
				Libraries: libs,
			})
		}
	}
	return results, nil
}

func mergePkgs(pkgs, pkgsFromCommands []types.Package) []types.Package {
	// pkg has priority over pkgsFromCommands
	uniqPkgs := map[string]struct{}{}
	for _, pkg := range pkgs {
		uniqPkgs[pkg.Name] = struct{}{}
	}
	for _, pkg := range pkgsFromCommands {
		if _, ok := uniqPkgs[pkg.Name]; ok {
			continue
		}
		pkgs = append(pkgs, pkg)
	}
	return pkgs
}
