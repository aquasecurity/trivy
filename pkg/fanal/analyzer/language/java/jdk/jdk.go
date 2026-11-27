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
		// Legacy formats:
		//   1.8.0_432-b06    -> 8.0.432+6
		//   1.8.0-ea         -> 8.0-ea
		//   1.8.0-ea-b123    -> 8.0-ea+123
		//   1.8.0_432-ea-b06 -> 8.0.432-ea+6
		base, suffix, hasDash := strings.Cut(after, "-")
		base = strings.ReplaceAll(base, "_", ".")
		if err := validateNumericVersion(base); err != nil {
			return "", xerrors.Errorf("invalid JDK version %q: %w", raw, err)
		}
		var pre string
		var build int
		var hasBuild bool
		if hasDash {
			for part := range strings.SplitSeq(suffix, "-") {
				if part == "" {
					continue
				}
				if !hasBuild && strings.HasPrefix(part, "b") {
					rest := strings.TrimPrefix(part, "b")
					if rest != "" && isAllDigits(rest) {
						if bNum, err := strconv.Atoi(rest); err == nil {
							build = bNum
							hasBuild = true
							continue
						}
					}
				}
				if pre == "" && !hasBuild && !strings.EqualFold(part, "ga") && isAlphaNumeric(part) {
					pre = part
				}
			}
		}
		return formatVersion(base, pre, build, hasBuild), nil
	}

	// JEP 322 formats:
	//   $VNUM(-$PRE)?+$BUILD(-$OPT)?
	//   $VNUM-$PRE(-$OPT)?
	//   $VNUM(+-$OPT)?
	beforePlus, afterPlus, hasPlus := strings.Cut(raw, "+")
	base, preAndOpt, hasDash := strings.Cut(beforePlus, "-")
	if err := validateNumericVersion(base); err != nil {
		return "", xerrors.Errorf("invalid JDK version %q: %w", raw, err)
	}
	var pre string
	if hasDash {
		candidate, _, _ := strings.Cut(preAndOpt, "-")
		if candidate != "" && isAlphaNumeric(candidate) {
			pre = candidate
		}
	}
	var build int
	var hasBuild bool
	if hasPlus {
		digits := leadingDigits(afterPlus)
		if digits != "" {
			if bNum, err := strconv.Atoi(digits); err == nil {
				build = bNum
				hasBuild = true
			}
		}
	}
	return formatVersion(base, pre, build, hasBuild), nil
}

func formatVersion(base, pre string, build int, hasBuild bool) string {
	var b strings.Builder
	b.WriteString(base)
	if pre != "" {
		b.WriteByte('-')
		b.WriteString(pre)
	}
	if hasBuild {
		fmt.Fprintf(&b, "+%d", build)
	}
	return b.String()
}

func validateNumericVersion(ver string) error {
	if ver == "" {
		return xerrors.New("empty version")
	}
	for part := range strings.SplitSeq(ver, ".") {
		if part == "" || !isAllDigits(part) {
			return xerrors.Errorf("invalid numeric segment %q", part)
		}
	}
	return nil
}

func isAllDigits(s string) bool {
	for i := range len(s) {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

func isAlphaNumeric(s string) bool {
	for i := range len(s) {
		c := s[i]
		isDigit := c >= '0' && c <= '9'
		isLower := c >= 'a' && c <= 'z'
		isUpper := c >= 'A' && c <= 'Z'
		if !isDigit && !isLower && !isUpper {
			return false
		}
	}
	return s != ""
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
