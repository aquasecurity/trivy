package apk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	builtinos "os"
	"sort"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

const (
	envApkIndexArchiveURL = "FANAL_APK_INDEX_ARCHIVE_URL"
	analyzerVersion       = 1
)

var defaultApkIndexArchiveURL = "https://raw.githubusercontent." +
	"com/knqyf263/apkIndex-archive/master/alpine/v%s/main/x86_64/history.json"

func init() {
	analyzer.RegisterConfigAnalyzer(analyzer.TypeApkCommand, newAlpineCmdAnalyzer)
}

type alpineCmdAnalyzer struct {
	apkIndexArchiveURL string
}

func newAlpineCmdAnalyzer(_ analyzer.ConfigAnalyzerOptions) (analyzer.ConfigAnalyzer, error) {
	apkIndexArchiveURL := defaultApkIndexArchiveURL
	if builtinos.Getenv(envApkIndexArchiveURL) != "" {
		apkIndexArchiveURL = builtinos.Getenv(envApkIndexArchiveURL)
	}
	return alpineCmdAnalyzer{apkIndexArchiveURL: apkIndexArchiveURL}, nil
}

type apkIndex struct {
	Package map[string]archive
	Provide provide
}

type archive struct {
	Origin       string
	Versions     version
	Dependencies []string
	Provides     []string
}

type provide struct {
	SO      map[string]apk // package which provides the shared object
	Package map[string]apk // package which provides the package
}

type apk struct {
	Package  string
	Versions version
}

type version map[string]int

func (a alpineCmdAnalyzer) Analyze(_ context.Context, input analyzer.ConfigAnalysisInput) (*analyzer.ConfigAnalysisResult, error) {
	if input.Config == nil {
		return nil, nil
	}
	var apkIndexArchive *apkIndex
	var err error
	if apkIndexArchive, err = a.fetchApkIndexArchive(input.OS); err != nil {
		log.Println(err)
		return nil, xerrors.Errorf("failed to fetch apk index archive: %w", err)
	}

	pkgs := a.parseConfig(apkIndexArchive, input.Config)
	if len(pkgs) == 0 {
		return nil, nil
	}

	return &analyzer.ConfigAnalysisResult{
		HistoryPackages: pkgs,
	}, nil
}
func (a alpineCmdAnalyzer) fetchApkIndexArchive(targetOS types.OS) (*apkIndex, error) {
	// 3.9.3 => 3.9
	osVer := targetOS.Name
	if strings.Count(osVer, ".") > 1 {
		osVer = osVer[:strings.LastIndex(osVer, ".")]
	}

	url := fmt.Sprintf(a.apkIndexArchiveURL, osVer)
	var reader io.Reader
	if strings.HasPrefix(url, "file://") {
		var err error
		reader, err = builtinos.Open(strings.TrimPrefix(url, "file://"))
		if err != nil {
			return nil, xerrors.Errorf("failed to read APKINDEX archive file: %w", err)
		}
		defer reader.(*builtinos.File).Close()
	} else {
		// nolint
		resp, err := http.Get(url)
		if err != nil {
			return nil, xerrors.Errorf("failed to fetch APKINDEX archive: %w", err)
		}
		defer resp.Body.Close()
		reader = resp.Body
	}
	apkIndexArchive := &apkIndex{}
	if err := json.NewDecoder(reader).Decode(apkIndexArchive); err != nil {
		return nil, xerrors.Errorf("failed to decode APKINDEX JSON: %w", err)
	}

	return apkIndexArchive, nil
}

func (a alpineCmdAnalyzer) parseConfig(apkIndexArchive *apkIndex, config *v1.ConfigFile) (packages []types.Package) {
	envs := make(map[string]string)
	for _, env := range config.Config.Env {
		index := strings.Index(env, "=")
		envs["$"+env[:index]] = env[index+1:]
	}

	uniqPkgs := make(map[string]types.Package)
	for _, history := range config.History {
		pkgs := a.parseCommand(history.CreatedBy, envs)
		pkgs = a.resolveDependencies(apkIndexArchive, pkgs)
		results := a.guessVersion(apkIndexArchive, pkgs, history.Created.Time)
		for _, result := range results {
			result.Identifier.UID = dependency.UID("", result)
			uniqPkgs[result.Name] = result
		}
	}

	return lo.Values(uniqPkgs)
}

func (a alpineCmdAnalyzer) parseCommand(command string, envs map[string]string) (pkgs []string) {
	if strings.Contains(command, "#(nop)") {
		return nil
	}

	command = strings.TrimPrefix(command, "/bin/sh -c")
	var commands []string
	for _, cmd := range strings.Split(command, "&&") {
		for _, c := range strings.Split(cmd, ";") {
			commands = append(commands, strings.TrimSpace(c))
		}
	}
	for _, cmd := range commands {
		if !strings.HasPrefix(cmd, "apk") {
			continue
		}

		var add bool
		for _, field := range strings.Fields(cmd) {
			switch {
			case strings.HasPrefix(field, "-") || strings.HasPrefix(field, "."):
				continue
			case field == "add":
				add = true
			case add:
				if strings.HasPrefix(field, "$") {
					pkgs = append(pkgs, strings.Fields(envs[field])...)
					continue
				}
				pkgs = append(pkgs, field)
			}
		}
	}
	return pkgs
}
func (a alpineCmdAnalyzer) resolveDependencies(apkIndexArchive *apkIndex, originalPkgs []string) (pkgs []string) {
	uniqPkgs := set.New[string]()
	for _, pkgName := range originalPkgs {
		if uniqPkgs.Contains(pkgName) {
			continue
		}

		seenPkgs := set.New[string]()
		for _, p := range a.resolveDependency(apkIndexArchive, pkgName, seenPkgs) {
			uniqPkgs.Append(p)
		}
	}
	return uniqPkgs.Items()
}

func (a alpineCmdAnalyzer) resolveDependency(apkIndexArchive *apkIndex, pkgName string,
	seenPkgs set.Set[string]) (pkgNames []string) {
	pkg, ok := apkIndexArchive.Package[pkgName]
	if !ok {
		return nil
	}
	if seenPkgs.Contains(pkgName) {
		return nil
	}
	seenPkgs.Append(pkgName)

	pkgNames = append(pkgNames, pkgName)
	for _, dependency := range pkg.Dependencies {
		// sqlite-libs=3.26.0-r3 => sqlite-libs
		dependency, _, _ = strings.Cut(dependency, "=")

		if strings.HasPrefix(dependency, "so:") {
			soProvidePkg := apkIndexArchive.Provide.SO[dependency[3:]].Package
			pkgNames = append(pkgNames, a.resolveDependency(apkIndexArchive, soProvidePkg, seenPkgs)...)
			continue
		} else if strings.HasPrefix(dependency, "pc:") || strings.HasPrefix(dependency, "cmd:") {
			continue
		}
		pkgProvidePkg, ok := apkIndexArchive.Provide.Package[dependency]
		if ok {
			pkgNames = append(pkgNames, a.resolveDependency(apkIndexArchive, pkgProvidePkg.Package, seenPkgs)...)
			continue
		}
		pkgNames = append(pkgNames, a.resolveDependency(apkIndexArchive, dependency, seenPkgs)...)
	}
	return pkgNames
}

type historyVersion struct {
	Version string
	BuiltAt int
}

func (a alpineCmdAnalyzer) guessVersion(apkIndexArchive *apkIndex, originalPkgs []string,
	createdAt time.Time) (pkgs []types.Package) {
	for _, pkg := range originalPkgs {
		archive, ok := apkIndexArchive.Package[pkg]
		if !ok {
			continue
		}

		var historyVersions []historyVersion
		for version, builtAt := range archive.Versions {
			historyVersions = append(historyVersions, historyVersion{
				Version: version,
				BuiltAt: builtAt,
			})
		}
		sort.Slice(historyVersions, func(i, j int) bool {
			return historyVersions[i].BuiltAt < historyVersions[j].BuiltAt
		})

		createdUnix := int(createdAt.Unix())
		var candidateVersion string
		for _, historyVersion := range historyVersions {
			if historyVersion.BuiltAt <= createdUnix {
				candidateVersion = historyVersion.Version
			} else if createdUnix < historyVersion.BuiltAt {
				break
			}
		}
		if candidateVersion == "" {
			continue
		}

		pkgs = append(pkgs, types.Package{
			Name:    pkg,
			Version: candidateVersion,
		})

		// Add origin package name
		if archive.Origin != "" && archive.Origin != pkg {
			pkgs = append(pkgs, types.Package{
				Name:    archive.Origin,
				Version: candidateVersion,
			})
		}
	}
	return pkgs
}

func (a alpineCmdAnalyzer) Required(targetOS types.OS) bool {
	return targetOS.Family == types.Alpine
}

func (a alpineCmdAnalyzer) Type() analyzer.Type {
	return analyzer.TypeApkCommand
}

func (a alpineCmdAnalyzer) Version() int {
	return analyzerVersion
}
