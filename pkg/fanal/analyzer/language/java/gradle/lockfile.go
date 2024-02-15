package gradle

import (
	"context"
	"encoding/xml"
	"fmt"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/samber/lo"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/gradle/lockfile"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGradleLock, newGradleLockAnalyzer)
}

const (
	version        = 2
	fileNameSuffix = "gradle.lockfile"
)

// gradleLockAnalyzer analyzes '*gradle.lockfile'
type gradleLockAnalyzer struct {
	parser godeptypes.Parser
}

func newGradleLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gradleLockAnalyzer{
		parser: lockfile.NewParser(),
	}, nil
}

func (a gradleLockAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	licenses, err := findLicenses()
	if err != nil {
		log.Logger.Warnf("Unable to get licenses: %s", err)
	}

	required := func(path string, d fs.DirEntry) bool {
		return a.Required(path, nil)
	}

	var apps []types.Application
	err = fsutils.WalkDir(input.FS, ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		var app *types.Application
		app, err = language.Parse(types.Pub, path, r, a.parser)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}

		if app == nil {
			return nil
		}
		for _, lib := range app.Libraries {
			lib.Licenses = licenses[lib.ID]
		}

		sort.Sort(app.Libraries)
		apps = append(apps, *app)
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a gradleLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, fileNameSuffix)
}

func (a gradleLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGradleLock
}

func (a gradleLockAnalyzer) Version() int {
	return version
}

func findLicenses() (map[string][]string, error) {
	// https://docs.gradle.org/current/userguide/directory_layout.html
	cacheDir := os.Getenv("GRADLE_USER_HOME")
	if cacheDir == "" {
		if runtime.GOOS == "windows" {
			cacheDir = filepath.Join(os.Getenv("%HOMEPATH%"), ".gradle")
		} else {
			cacheDir = filepath.Join(os.Getenv("HOME"), ".gradle")
		}
	}
	cacheDir = filepath.Join(cacheDir, "caches")

	if !fsutils.DirExists(cacheDir) {
		log.Logger.Warnf("Unable to get licanses. Gradle cache dir doesn't exist.")
		return nil, nil
	}

	var licenses = make(map[string][]string)
	err := filepath.WalkDir(cacheDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		} else if !d.Type().IsRegular() {
			return nil
		}
		if filepath.Ext(path) != ".pom" {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return xerrors.Errorf("file (%s) open error: %w", path, err)
		}
		defer func() { _ = f.Close() }()

		var pom pomXML
		if err = xml.NewDecoder(f).Decode(&pom); err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
		}

		// Skip if pom file doesn't contain licenses
		if len(pom.Licenses.License) == 0 {
			return nil
		}

		// If pom file doesn't contain GroupID or Version:
		// find these values from filepath
		// e.g. caches/modules-2/files-2.1/com.google.code.gson/gson/2.9.1/f0cf3edcef8dcb74d27cb427544a309eb718d772/gson-2.9.1.pom
		dirs := strings.Split(filepath.ToSlash(path), "/")
		groupID := pom.GroupId
		if groupID == "" {
			groupID = dirs[len(dirs)-5]
		}
		ver := pom.Version
		if ver == "" {
			ver = dirs[len(dirs)-3]
		}
		id := fmt.Sprintf("%s:%s:%s", groupID, pom.ArtifactId, ver)

		licenses[id] = lo.Map(pom.Licenses.License, func(l pomLicense, _ int) string {
			return l.Name
		})
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("gradle licenses walk error: %w", err)
	}

	return licenses, nil
}

type pomXML struct {
	GroupId    string      `xml:"groupId"`
	ArtifactId string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Licenses   pomLicenses `xml:"licenses"`
}

type pomLicenses struct {
	Text    string       `xml:",chardata"`
	License []pomLicense `xml:"license"`
}

type pomLicense struct {
	Name string `xml:"name"`
}
