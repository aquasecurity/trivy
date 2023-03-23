package language

import (
	"crypto/sha256"
	"fmt"
	"github.com/aquasecurity/trivy/pkg/log"
	"io"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
)

func Analyze(fileType, filePath string, r dio.ReadSeekerAt, parser godeptypes.Parser) (*analyzer.AnalysisResult, error) {
	parsedLibs, parsedDependencies, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return ToAnalysisResult(fileType, filePath, "", parsedLibs, parsedDependencies), nil
}

func ToApplication(fileType, filePath, libFilePath string, r dio.ReadSeekerAt, libs []godeptypes.Library, depGraph []godeptypes.Dependency) *types.Application {
	if len(libs) == 0 {
		return nil
	}

	checksum, err := calculateChecksum(r)
	if err != nil {
		log.Logger.Warnf("unable to get checksum for %s: %s", filePath, err)
	}
	deps := make(map[string][]string)
	for _, dep := range depGraph {
		deps[dep.ID] = dep.DependsOn
	}

	var pkgs []types.Package
	for _, lib := range libs {
		var licenses []string
		if lib.License != "" {
			licenses = strings.Split(lib.License, ",")
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
		pkgs = append(pkgs, types.Package{
			ID:        lib.ID,
			Name:      lib.Name,
			Version:   lib.Version,
			FilePath:  libFilePath,
			Indirect:  lib.Indirect,
			Licenses:  licenses,
			DependsOn: deps[lib.ID],
			Locations: locs,
			Checksum:  checksum,
		})
	}

	return &types.Application{
		Type:      fileType,
		FilePath:  filePath,
		Libraries: pkgs,
	}
}

func ToAnalysisResult(fileType, filePath, libFilePath string, libs []godeptypes.Library, depGraph []godeptypes.Dependency) *analyzer.AnalysisResult {
	app := ToApplication(fileType, filePath, libFilePath, nil, libs, depGraph)
	if app == nil {
		return nil
	}

	return &analyzer.AnalysisResult{Applications: []types.Application{*app}}
}

func calculateChecksum(r dio.ReadSeekerAt) (string, error) {
	// return reader to start after it has been read in analyzer
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", xerrors.Errorf("unable to seek: %w", err)
	}

	// calculate checksum
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", xerrors.Errorf("unable to calculate checksum: %w", err)
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
