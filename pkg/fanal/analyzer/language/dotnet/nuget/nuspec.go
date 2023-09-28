package nuget

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const nuspecExt = "nuspec"

// https://learn.microsoft.com/en-us/nuget/reference/nuspec
type Package struct {
	Metadata Metadata `xml:"metadata"`
}

type Metadata struct {
	License License `xml:"license"`
}

type License struct {
	Text string `xml:",chardata"`
	Type string `xml:"type,attr"`
}

type nuspecParser struct {
	packagesDir string // global packages folder - https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
}

func newNuspecParser() nuspecParser {
	// https: //learn.microsoft.com/en-us/nuget/consume-packages/managing-the-global-packages-and-cache-folders
	packagesDir := os.Getenv("NUGET_PACKAGES")
	if packagesDir == "" {
		packagesDir = filepath.Join(os.Getenv("HOME"), ".nuget", "packages")
	}

	if !fsutils.DirExists(packagesDir) {
		log.Logger.Debugf("The nuget packages directory couldn't be found. License search disabled")
		return nuspecParser{}
	}

	return nuspecParser{
		packagesDir: packagesDir,
	}
}

func (p nuspecParser) findLicense(name, version string) ([]string, error) {
	if p.packagesDir == "" {
		return nil, nil
	}

	// package path uses lowercase letters only
	// e.g. `$HOME/.nuget/packages/newtonsoft.json/13.0.3/newtonsoft.json.nuspec`
	// for `Newtonsoft.Json` v13.0.3
	name = strings.ToLower(name)
	version = strings.ToLower(version)

	nuspecFileName := fmt.Sprintf("%s.%s", name, nuspecExt)
	path := filepath.Join(p.packagesDir, name, version, nuspecFileName)

	f, err := os.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("unable to open %q file: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	var pkg Package
	if err = xml.NewDecoder(f).Decode(&pkg); err != nil {
		return nil, xerrors.Errorf("unable to decode %q file: %w", path, err)
	}

	if license := pkg.Metadata.License; license.Type != "expression" || license.Text == "" {
		return nil, nil
	}
	return []string{pkg.Metadata.License.Text}, nil
}
