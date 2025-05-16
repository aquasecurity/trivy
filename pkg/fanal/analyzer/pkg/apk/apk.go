package apk

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"slices"
	"sort"
	"strings"

	apkVersion "github.com/knqyf263/go-apk-version"
	"github.com/samber/lo"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
)

func init() {
	analyzer.RegisterAnalyzer(newAlpinePkgAnalyzer())
}

const analyzerVersion = 2

var requiredFiles = []string{"lib/apk/db/installed"}

type alpinePkgAnalyzer struct{}

func newAlpinePkgAnalyzer() *alpinePkgAnalyzer { return &alpinePkgAnalyzer{} }

func (a alpinePkgAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	ctx = log.WithContextPrefix(ctx, "apk")
	scanner := bufio.NewScanner(input.Content)
	parsedPkgs, installedFiles := a.parseApkInfo(ctx, scanner)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: parsedPkgs,
			},
		},
		SystemInstalledFiles: installedFiles,
	}, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(ctx context.Context, scanner *bufio.Scanner) ([]types.Package, []string) {
	var (
		pkgs           []types.Package
		pkg            types.Package
		version        string
		dir            string
		installedFiles []string
		provides       = make(map[string]string) // for dependency graph
	)

	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if !pkg.Empty() {
				pkgs = append(pkgs, pkg)
			}
			pkg = types.Package{}
			continue
		}

		// ref. https://wiki.alpinelinux.org/wiki/Apk_spec
		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = line[2:]
			if !apkVersion.Valid(version) {
				log.WarnContext(ctx, "Invalid version found",
					log.String("name", pkg.Name), log.String("version", version))
				continue
			}
			pkg.Version = version
		case "o:":
			origin := line[2:]
			pkg.SrcName = origin
			pkg.SrcVersion = version
		case "L:":
			pkg.Licenses = a.parseLicense(line)
		case "F:":
			dir = line[2:]
		case "R:":
			absPath := path.Join(dir, line[2:])
			pkg.InstalledFiles = append(pkg.InstalledFiles, absPath)
			installedFiles = append(installedFiles, absPath)
		case "p:": // provides (corresponds to provides in PKGINFO, concatenated by spaces into a single line)
			a.parseProvides(line, pkg.ID, provides)
		case "D:": // dependencies (corresponds to depend in PKGINFO, concatenated by spaces into a single line)
			pkg.DependsOn = a.parseDependencies(line)
		case "A:":
			pkg.Arch = line[2:]
		case "C:":
			d := a.decodeChecksumLine(ctx, line)
			if d != "" {
				pkg.Digest = d
			}
		}

		if pkg.Name != "" && pkg.Version != "" {
			pkg.ID = fmt.Sprintf("%s@%s", pkg.Name, pkg.Version)

			// Dependencies could be package names or provides, so package names are stored as provides here.
			// e.g. D:scanelf so:libc.musl-x86_64.so.1
			provides[pkg.Name] = pkg.ID
		}
	}
	// in case of last paragraph
	if !pkg.Empty() {
		pkgs = append(pkgs, pkg)
	}

	pkgs = a.uniquePkgs(pkgs)

	// Replace dependencies with package IDs
	a.consolidateDependencies(pkgs, provides)

	return pkgs, installedFiles
}

func (a alpinePkgAnalyzer) trimRequirement(s string) string {
	// Trim version requirements
	// e.g.
	//   so:libssl.so.1.1=1.1 => so:libssl.so.1.1
	//   musl>=1.2 => musl
	if strings.ContainsAny(s, "<>=") {
		s = s[:strings.IndexAny(s, "><=")]
	}
	return s
}

func (a alpinePkgAnalyzer) parseLicense(line string) []string {
	// Remove "L:" before split
	return licensing.LaxSplitLicenses(line[2:])
}

func (a alpinePkgAnalyzer) parseProvides(line, pkgID string, provides map[string]string) {
	for _, p := range strings.Fields(line[2:]) {
		p = a.trimRequirement(p)

		// Assume name ("P:") and version ("V:") are defined before provides ("p:")
		provides[p] = pkgID
	}
}

func (a alpinePkgAnalyzer) parseDependencies(line string) []string {
	line = line[2:] // Remove "D:"
	return lo.FilterMap(strings.Fields(line), func(d string, _ int) (string, bool) {
		// e.g. D:!uclibc-utils scanelf musl=1.1.14-r10 so:libc.musl-x86_64.so.1
		if strings.HasPrefix(d, "!") {
			return "", false
		}
		return a.trimRequirement(d), true
	})
}

func (a alpinePkgAnalyzer) consolidateDependencies(pkgs []types.Package, provides map[string]string) {
	for i := range pkgs {
		// e.g. libc6 => libc6@2.31-13+deb11u4
		pkgs[i].DependsOn = lo.FilterMap(pkgs[i].DependsOn, func(d string, _ int) (string, bool) {
			if pkgID, ok := provides[d]; ok {
				return pkgID, true
			}
			return "", false
		})
		sort.Strings(pkgs[i].DependsOn)
		pkgs[i].DependsOn = slices.Compact(pkgs[i].DependsOn)

		if len(pkgs[i].DependsOn) == 0 {
			pkgs[i].DependsOn = nil
		}
	}
}

func (a alpinePkgAnalyzer) uniquePkgs(pkgs []types.Package) (uniqPkgs []types.Package) {
	uniq := set.New[string]()
	for _, pkg := range pkgs {
		if uniq.Contains(pkg.Name) {
			continue
		}
		uniqPkgs = append(uniqPkgs, pkg)
		uniq.Append(pkg.Name)
	}
	return uniqPkgs
}

func (a alpinePkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return slices.Contains(requiredFiles, filePath)
}

func (a alpinePkgAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApk
}

func (a alpinePkgAnalyzer) Version() int {
	return analyzerVersion
}

// StaticPaths returns a list of static file paths to analyze
func (a alpinePkgAnalyzer) StaticPaths() []string {
	return requiredFiles
}

// decodeChecksumLine decodes checksum line
func (a alpinePkgAnalyzer) decodeChecksumLine(ctx context.Context, line string) digest.Digest {
	if len(line) < 2 {
		log.DebugContext(ctx, "Unable to decode checksum line of apk package", log.String("line", line))
		return ""
	}
	// https://wiki.alpinelinux.org/wiki/Apk_spec#Package_Checksum_Field
	// https://stackoverflow.com/a/71712569
	alg := digest.MD5
	d := line[2:]
	if strings.HasPrefix(d, "Q1") {
		alg = digest.SHA1
		d = d[2:] // remove `Q1` prefix
	}

	decodedDigestString, err := base64.StdEncoding.DecodeString(d)
	if err != nil {
		log.DebugContext(ctx, "Unable to decode digest", log.Err(err))
		return ""
	}
	h := hex.EncodeToString(decodedDigestString)
	return digest.NewDigestFromString(alg, h)
}
