package gradle

import (
	"encoding/xml"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/net/html/charset"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type pomXML struct {
	GroupId      string       `xml:"groupId"`
	ArtifactId   string       `xml:"artifactId"`
	Version      string       `xml:"version"`
	Properties   Properties   `xml:"properties"`
	Dependencies Dependencies `xml:"dependencies"`
	Licenses     Licenses     `xml:"licenses"`
}
type Dependencies struct {
	Dependency []Dependency `xml:"dependency"`
}

type Dependency struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

type Licenses struct {
	License []License `xml:"license"`
}

type License struct {
	Name string `xml:"name"`
}

type Properties map[string]string

type property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (props *Properties) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	*props = Properties{}
	for {
		var p property
		err := d.Decode(&p)
		if err == io.EOF {
			break
		} else if err != nil {
			return xerrors.Errorf("XML decode error: %w", err)
		}

		(*props)[p.XMLName.Local] = p.Value
	}
	return nil
}

func parsePoms() (map[string]pomXML, error) {
	cacheDir := detectCacheDir()
	// Cache dir is not found
	if cacheDir == "" {
		return nil, nil
	}

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Ext(path) == ".pom"
	}

	var poms = make(map[string]pomXML)
	err := fsutils.WalkDir(os.DirFS(cacheDir), ".", required, func(path string, _ fs.DirEntry, r io.Reader) error {
		pom, err := parsePom(r, path)
		if err != nil {
			log.Logger.Debugf("Unable to parse %q: %s", path, err)
			return nil
		}

		if pom.ArtifactId != "" {
			poms[packageID(pom.GroupId, pom.ArtifactId, pom.Version)] = pom
		}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("gradle licenses walk error: %w", err)
	}

	return poms, nil
}

func parsePom(r io.Reader, path string) (pomXML, error) {
	pom := pomXML{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(&pom); err != nil {
		return pomXML{}, xerrors.Errorf("xml decode error: %w", err)
	}

	// We only need pom's with licenses or dependencies
	if len(pom.Licenses.License) == 0 && len(pom.Dependencies.Dependency) == 0 {
		return pomXML{}, nil
	}

	// If pom file doesn't contain GroupID or Version:
	// find these values from filepath
	// e.g. caches/modules-2/files-2.1/com.google.code.gson/gson/2.9.1/f0cf3edcef8dcb74d27cb427544a309eb718d772/gson-2.9.1.pom
	dirs := strings.Split(filepath.ToSlash(path), "/")
	if pom.GroupId == "" {
		pom.GroupId = dirs[len(dirs)-5]
	}
	if pom.Version == "" {
		pom.Version = dirs[len(dirs)-3]
	}

	if err := pom.resolveDependencyVersions(); err != nil {
		return pomXML{}, xerrors.Errorf("unable to resolve dependency version: %w", err)
	}

	return pom, nil
}

// resolveDependencyVersions resolves versions from properties
func (pom *pomXML) resolveDependencyVersions() error {
	for i, dep := range pom.Dependencies.Dependency {
		if strings.HasPrefix(dep.Version, "${") && strings.HasSuffix(dep.Version, "}") {
			dep.Version = strings.TrimPrefix(strings.TrimSuffix(dep.Version, "}"), "${")
			if resolvedVer, ok := pom.Properties[dep.Version]; ok {
				pom.Dependencies.Dependency[i].Version = resolvedVer
			} else if dep.Version == "${project.version}" {
				pom.Dependencies.Dependency[i].Version = dep.Version
			} else {
				// We use simplified logic to resolve properties.
				// If necessary, update and use the logic for maven pom's
				return xerrors.Errorf("Unable to resolve %q version. Please open a new discussion to update the Trivy logic.", dep.Version)
			}
		}
	}
	return nil
}

func detectCacheDir() string {
	// https://docs.gradle.org/current/userguide/directory_layout.html
	dir := os.Getenv("GRADLE_USER_HOME")
	if dir == "" {
		if runtime.GOOS == "windows" {
			dir = filepath.Join(os.Getenv("%HOMEPATH%"), ".gradle")
		} else {
			dir = filepath.Join(os.Getenv("HOME"), ".gradle")
		}
	}
	dir = filepath.Join(dir, "caches")

	if !fsutils.DirExists(dir) {
		log.Logger.Debug("Unable to get licenses and dependsOn. Gradle cache dir doesn't exist.")
		return ""
	}
	return dir
}
