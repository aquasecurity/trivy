package language

import (
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser interface {
	// Parse parses the dependency file
	Parse(r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error)
}

// Analyze returns an analysis result of the lock file
func Analyze(fileType types.LangType, filePath string, r xio.ReadSeekerAt, parser Parser) (*analyzer.AnalysisResult, error) {
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
func AnalyzePackage(fileType types.LangType, filePath string, r xio.ReadSeekerAt, parser Parser, checksum bool) (*analyzer.AnalysisResult, error) {
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
func Parse(fileType types.LangType, filePath string, r io.Reader, parser Parser) (*types.Application, error) {
	rr, err := xio.NewReadSeekerAt(r)
	if err != nil {
		return nil, xerrors.Errorf("reader error: %w", err)
	}
	parsedPkgs, parsedDependencies, err := parser.Parse(rr)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return toApplication(fileType, filePath, "", nil, parsedPkgs, parsedDependencies), nil
}

// ParsePackage returns a parsed result of the package file
func ParsePackage(fileType types.LangType, filePath string, r xio.ReadSeekerAt, parser Parser, checksum bool) (*types.Application, error) {
	parsedPkgs, parsedDependencies, err := parser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse %s: %w", filePath, err)
	}

	// The reader is not passed if the checksum is not necessarily calculated.
	if !checksum {
		r = nil
	}

	// The file path of each library should be empty in case of dependency list such as lock file
	// since they all will be the same path.
	return toApplication(fileType, filePath, filePath, r, parsedPkgs, parsedDependencies), nil
}

func toApplication(fileType types.LangType, filePath, libFilePath string, r xio.ReadSeekerAt, pkgs []types.Package, depGraph []types.Dependency) *types.Application {
	if len(pkgs) == 0 {
		return nil
	}

	// Calculate the file digest when one of `spdx` formats is selected
	d, err := calculateDigest(r)
	if err != nil {
		log.Warn("Unable to get checksum", log.FilePath(filePath), log.Err(err))
	}

	deps := make(map[string][]string)
	for _, dep := range depGraph {
		deps[dep.ID] = dep.DependsOn
	}

	for i, pkg := range pkgs {
		// This file path is populated for virtual file paths within archives, such as nested JAR files.
		if pkg.FilePath == "" {
			pkgs[i].FilePath = libFilePath
		}
		pkgs[i].DependsOn = deps[pkg.ID]
		pkgs[i].Digest = d
		pkgs[i].Indirect = isIndirect(pkg.Relationship) // For backward compatibility

		for j, license := range pkg.Licenses {
			pkgs[i].Licenses[j] = licensing.Normalize(license)
		}
	}

	return &types.Application{
		Type:     fileType,
		FilePath: filePath,
		Packages: pkgs,
	}
}

func calculateDigest(r xio.ReadSeekerAt) (digest.Digest, error) {
	if r == nil {
		return "", nil
	}
	// return reader to start after it has been read in analyzer
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", xerrors.Errorf("unable to seek: %w", err)
	}

	return digest.CalcSHA1(r)
}

func isIndirect(rel types.Relationship) bool {
	switch rel {
	case types.RelationshipIndirect:
		return true
	default:
		return false
	}
}
