package jdk

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	version      = 1
	requiredFile = "release"
)

func init() {
	analyzer.RegisterAnalyzer(&jdkAnalyzer{})
}

type parser struct{}

func (parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	var javaVer, runtimeVer string
	var hasMarker bool

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(strings.TrimSpace(v), `"`)
		switch strings.TrimSpace(k) {
		case "JAVA_VERSION":
			javaVer = v
		case "JAVA_RUNTIME_VERSION":
			runtimeVer = v
			if v != "" {
				hasMarker = true
			}
		case "IMPLEMENTOR", "MODULES":
			if v != "" {
				hasMarker = true
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	if javaVer == "" || !hasMarker {
		return nil, nil, nil
	}

	ver, err := normalizeVersion(javaVer, runtimeVer)
	if err != nil {
		return nil, nil, err
	}

	return []types.Package{{
		ID:      dependency.ID(types.JDK, "openjdk", ver),
		Name:    "openjdk",
		Version: ver,
	}}, nil, nil
}

func normalizeVersion(javaVer, runtimeVer string) (string, error) {
	raw := runtimeVer
	if raw == "" {
		raw = javaVer
	}

	if after, ok := strings.CutPrefix(raw, "1."); ok {
		// Legacy 1.8.0_432-b06 -> 8.0.432+6
		base, buildPart, hasDash := strings.Cut(after, "-")
		base = strings.ReplaceAll(base, "_", ".")
		if err := validateNumericPrefix(base); err != nil {
			return "", xerrors.Errorf("invalid JDK version %q: %w", raw, err)
		}
		if hasDash && strings.HasPrefix(buildPart, "b") {
			digits := leadingDigits(strings.TrimPrefix(buildPart, "b"))
			if digits != "" {
				bNum, err := strconv.Atoi(digits)
				if err == nil {
					return fmt.Sprintf("%s+%d", base, bNum), nil
				}
			}
		}
		return base, nil
	}

	base, rest, hasPlus := strings.Cut(raw, "+")
	base, _, _ = strings.Cut(base, "-")
	if err := validateNumericPrefix(base); err != nil {
		return "", xerrors.Errorf("invalid JDK version %q: %w", raw, err)
	}
	if hasPlus {
		digits := leadingDigits(rest)
		if digits != "" {
			bNum, err := strconv.Atoi(digits)
			if err == nil {
				return fmt.Sprintf("%s+%d", base, bNum), nil
			}
		}
	}
	return base, nil
}

func validateNumericPrefix(ver string) error {
	first, _, _ := strings.Cut(ver, ".")
	if first == "" {
		return xerrors.New("empty major version")
	}
	if _, err := strconv.Atoi(first); err != nil {
		return err
	}
	return nil
}

func leadingDigits(s string) string {
	var i int
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

type jdkAnalyzer struct{}

func (jdkAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.AnalyzePackage(ctx, types.JDK, input.FilePath, input.Content, parser{}, input.Options.FileChecksum)
}

func (jdkAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filepath.ToSlash(filePath)) == requiredFile
}

func (jdkAnalyzer) Type() analyzer.Type { return analyzer.TypeJDK }

func (jdkAnalyzer) Version() int { return version }
