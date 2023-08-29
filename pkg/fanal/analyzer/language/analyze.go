package language

import (
	"io"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// Analyze returns an analysis result of the lock file
func Analyze(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser) (*analyzer.AnalysisResult, error) {
	app, err := Parse(fileType, filePath, r, parser)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	if app == nil {
		return nil, nil
	}

	return &analyzer.AnalysisResult{Applications: []types.Application{*app}}, nil
}

// AnalyzePackage returns an analysis result of the package file other than lock files
func AnalyzePackage(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser, checksum bool) (*analyzer.AnalysisResult, error) {
	app, err := ParsePackage(fileType, filePath, r, parser, checksum)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	if app == nil {
		return nil, nil
	}

	return &analyzer.AnalysisResult{Applications: []types.Application{*app}}, nil
}

// Parse returns a parsed result of the lock file
func Parse(fileType, filePath string, r io.Reader, parser godeptypes.Parser) (*types.Application, error) {
	rr, err := xio.NewReadSeekerAt(r)
	if err != nil {
		return nil, xerrors.Errorf("reader error: %w", err)
	}
	parsedLibs, parsedDependencies, err := parser.Parse(rr)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return toApplication(fileType, filePath, "", nil, parsedLibs, parsedDependencies), nil
}

// ParsePackage returns a parsed result of the package file
func ParsePackage(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser, checksum bool) (*types.Application, error) {
	parsedLibs, parsedDependencies, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The reader is not passed if the checksum is not necessarily calculated.
	if !checksum {
		r = nil
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return toApplication(fileType, filePath, filePath, r, parsedLibs, parsedDependencies), nil
}

func toApplication(fileType, filePath, libFilePath string, r dio.ReadSeekerAt, libs []godeptypes.Library, depGraph []godeptypes.Dependency) *types.Application {
	if len(libs) == 0 {
		return nil
	}

	// Calculate the file digest when one of `spdx` formats is selected
	d, err := calculateDigest(r)
	if err != nil {
		log.Logger.Warnf("Unable to get checksum for %s: %s", filePath, err)
	}

	deps := make(map[string][]string)
	for _, dep := range depGraph {
		deps[dep.ID] = dep.DependsOn
	}

	var pkgs []types.Package
	for _, lib := range libs {
		var licenses []string
		if lib.License != "" {
			licenses = licensing.SplitLicenses(lib.License)
			for i, license := range licenses {
				licenses[i] = licensing.Normalize(strings.TrimSpace(license))
			}
		}
		var locs []types.Location
		for _, loc := range lib.Locations {
			l := types.Location{
				StartLine: loc.StartLine,
				EndLine:   loc.EndLine,
			}
			locs = append(locs, l)
		}

		// This file path is populated for virtual file paths within archives, such as nested JAR files.
		libPath := libFilePath
		if lib.FilePath != "" {
			libPath = lib.FilePath
		}
		pkgs = append(pkgs, types.Package{
			ID:        lib.ID,
			Name:      lib.Name,
			Version:   lib.Version,
			Dev:       lib.Dev,
			FilePath:  libPath,
			Indirect:  lib.Indirect,
			Licenses:  licenses,
			DependsOn: deps[lib.ID],
			Locations: locs,
			Digest:    d,
		})
	}

	return &types.Application{
		Type:      fileType,
		FilePath:  filePath,
		Libraries: pkgs,
	}
}

func calculateDigest(r dio.ReadSeekerAt) (digest.Digest, error) {
	if r == nil {
		return "", nil
	}
	// return reader to start after it has been read in analyzer
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", xerrors.Errorf("unable to seek: %w", err)
	}

	return digest.CalcSHA1(r)
}
