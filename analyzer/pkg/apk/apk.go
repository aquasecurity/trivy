package apk

import (
	"bufio"
	"bytes"
	"log"
	"os"

	apkVersion "github.com/knqyf263/go-apk-version"

	"github.com/aquasecurity/fanal/analyzer"
	fos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&alpinePkgAnalyzer{})
}

var requiredFiles = []string{"lib/apk/db/installed"}

type alpinePkgAnalyzer struct{}

func (a alpinePkgAnalyzer) Analyze(target analyzer.AnalysisTarget) (*analyzer.AnalysisResult, error) {
	scanner := bufio.NewScanner(bytes.NewBuffer(target.Content))
	parsedPkgs := a.parseApkInfo(scanner)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: target.FilePath,
				Packages: parsedPkgs,
			},
		},
	}, nil
}

func (a alpinePkgAnalyzer) parseApkInfo(scanner *bufio.Scanner) (pkgs []types.Package) {
	var pkg types.Package
	var version string
	for scanner.Scan() {
		line := scanner.Text()

		// check package if paragraph end
		if len(line) < 2 {
			if analyzer.CheckPackage(&pkg) {
				pkgs = append(pkgs, pkg)
			}
			pkg = types.Package{}
			continue
		}

		switch line[:2] {
		case "P:":
			pkg.Name = line[2:]
		case "V:":
			version = string(line[2:])
			if !apkVersion.Valid(version) {
				log.Printf("Invalid Version Found : OS %s, Package %s, Version %s", "alpine", pkg.Name, version)
				continue
			}
			pkg.Version = version
		case "o:":
			origin := line[2:]
			pkg.SrcName = origin
			pkg.SrcVersion = version
		}
	}
	// in case of last paragraph
	if analyzer.CheckPackage(&pkg) {
		pkgs = append(pkgs, pkg)
	}

	return a.uniquePkgs(pkgs)
}
func (a alpinePkgAnalyzer) uniquePkgs(pkgs []types.Package) (uniqPkgs []types.Package) {
	uniq := map[string]struct{}{}
	for _, pkg := range pkgs {
		if _, ok := uniq[pkg.Name]; ok {
			continue
		}
		uniqPkgs = append(uniqPkgs, pkg)
		uniq[pkg.Name] = struct{}{}
	}
	return uniqPkgs
}

func (a alpinePkgAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a alpinePkgAnalyzer) Name() string {
	return fos.Alpine
}
