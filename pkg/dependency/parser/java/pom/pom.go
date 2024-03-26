package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"net/url"
	"reflect"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

type pom struct {
	filePath string
	content  *pomXML
}

func (p *pom) inherit(result analysisResult) {
	// Merge properties
	p.content.Properties = utils.MergeMaps(result.properties, p.content.Properties)

	art := p.artifact().Inherit(result.artifact)

	p.content.GroupId = art.GroupID
	p.content.ArtifactId = art.ArtifactID
	p.content.Licenses = art.ToPOMLicenses()

	if isProperty(art.Version.String()) {
		p.content.Version = evaluateVariable(art.Version.String(), p.content.Properties, nil)
	} else {
		p.content.Version = art.Version.String()
	}
}

func (p pom) properties() properties {
	props := p.content.Properties
	return utils.MergeMaps(props, p.projectProperties())
}

func (p pom) projectProperties() map[string]string {
	val := reflect.ValueOf(p.content).Elem()
	props := p.listProperties(val)

	// "version" and "groupId" elements could be inherited from parent.
	// https://maven.apache.org/pom.html#inheritance
	props["groupId"] = p.content.GroupId
	props["version"] = p.content.Version

	// https://maven.apache.org/pom.html#properties
	projectProperties := make(map[string]string)
	for k, v := range props {
		if strings.HasPrefix(k, "project.") {
			continue
		}

		// e.g. ${project.groupId}
		key := fmt.Sprintf("project.%s", k)
		projectProperties[key] = v

		// It is deprecated, but still available.
		// e.g. ${groupId}
		projectProperties[k] = v
	}

	return projectProperties
}

func (p pom) listProperties(val reflect.Value) map[string]string {
	props := make(map[string]string)
	for i := 0; i < val.NumField(); i++ {
		f := val.Type().Field(i)

		tag, ok := f.Tag.Lookup("xml")
		if !ok || strings.Contains(tag, ",") {
			// e.g. ",chardata"
			continue
		}

		switch f.Type.Kind() {
		case reflect.Slice:
			continue
		case reflect.Map:
			m := val.Field(i)
			for _, e := range m.MapKeys() {
				v := m.MapIndex(e)
				props[e.String()] = v.String()
			}
		case reflect.Struct:
			nestedProps := p.listProperties(val.Field(i))
			for k, v := range nestedProps {
				key := fmt.Sprintf("%s.%s", tag, k)
				props[key] = v
			}
		default:
			props[tag] = val.Field(i).String()
		}
	}
	return props
}

func (p pom) artifact() artifact {
	return newArtifact(p.content.GroupId, p.content.ArtifactId, p.content.Version, p.licenses(), p.content.Properties)
}

func (p pom) licenses() []string {
	return lo.FilterMap(p.content.Licenses.License, func(lic pomLicense, _ int) (string, bool) {
		return lic.Name, lic.Name != ""
	})
}

func (p pom) repositories(servers []Server) []string {
	var urls []string
	for _, rep := range p.content.Repositories.Repository {
		// Add only enabled repositories
		if rep.Releases.Enabled == "false" && rep.Snapshots.Enabled == "false" {
			continue
		}

		repoURL, err := url.Parse(rep.URL)
		if err != nil {
			log.Logger.Debugf("Unable to parse remote repository url: %s", err)
			continue
		}

		// Get the credentials from settings.xml based on matching server id
		// with the repository id from pom.xml and use it for accessing the repository url
		for _, server := range servers {
			if rep.ID == server.ID && server.Username != "" && server.Password != "" {
				repoURL.User = url.UserPassword(server.Username, server.Password)
				break
			}
		}

		log.Logger.Debugf("Adding repository %s: %s", rep.ID, rep.URL)
		urls = append(urls, repoURL.String())
	}
	return urls
}

type pomXML struct {
	Parent     pomParent   `xml:"parent"`
	GroupId    string      `xml:"groupId"`
	ArtifactId string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Licenses   pomLicenses `xml:"licenses"`
	Modules    struct {
		Text   string   `xml:",chardata"`
		Module []string `xml:"module"`
	} `xml:"modules"`
	Properties           properties `xml:"properties"`
	DependencyManagement struct {
		Text         string          `xml:",chardata"`
		Dependencies pomDependencies `xml:"dependencies"`
	} `xml:"dependencyManagement"`
	Dependencies pomDependencies `xml:"dependencies"`
	Repositories pomRepositories `xml:"repositories"`
}

type pomParent struct {
	GroupId      string `xml:"groupId"`
	ArtifactId   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
}

type pomLicenses struct {
	Text    string       `xml:",chardata"`
	License []pomLicense `xml:"license"`
}

type pomLicense struct {
	Name string `xml:"name"`
}

type pomDependencies struct {
	Text       string          `xml:",chardata"`
	Dependency []pomDependency `xml:"dependency"`
}

type pomDependency struct {
	Text       string        `xml:",chardata"`
	GroupID    string        `xml:"groupId"`
	ArtifactID string        `xml:"artifactId"`
	Version    string        `xml:"version"`
	Scope      string        `xml:"scope"`
	Optional   bool          `xml:"optional"`
	Exclusions pomExclusions `xml:"exclusions"`
	StartLine  int
	EndLine    int
}

type pomExclusions struct {
	Text      string         `xml:",chardata"`
	Exclusion []pomExclusion `xml:"exclusion"`
}

// ref. https://maven.apache.org/guides/introduction/introduction-to-optional-and-excludes-dependencies.html
type pomExclusion struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
}

func (d pomDependency) Name() string {
	return fmt.Sprintf("%s:%s", d.GroupID, d.ArtifactID)
}

// Resolve evaluates variables in the dependency and inherit some fields from dependencyManagement to the dependency.
func (d pomDependency) Resolve(props map[string]string, depManagement, rootDepManagement []pomDependency) pomDependency {
	// Evaluate variables
	dep := pomDependency{
		Text:       d.Text,
		GroupID:    evaluateVariable(d.GroupID, props, nil),
		ArtifactID: evaluateVariable(d.ArtifactID, props, nil),
		Version:    evaluateVariable(d.Version, props, nil),
		Scope:      evaluateVariable(d.Scope, props, nil),
		Optional:   d.Optional,
		Exclusions: d.Exclusions,
		StartLine:  d.StartLine,
		EndLine:    d.EndLine,
	}

	// If this dependency is managed in the root POM,
	// we need to overwrite fields according to the managed dependency.
	if managed, found := findDep(d.Name(), rootDepManagement); found { // dependencyManagement from the root POM
		if managed.Version != "" {
			dep.Version = evaluateVariable(managed.Version, props, nil)
		}
		if managed.Scope != "" {
			dep.Scope = evaluateVariable(managed.Scope, props, nil)
		}
		if managed.Optional {
			dep.Optional = managed.Optional
		}
		if len(managed.Exclusions.Exclusion) != 0 {
			dep.Exclusions = managed.Exclusions
		}
		return dep
	}

	// Inherit version, scope and optional from dependencyManagement if empty
	if managed, found := findDep(d.Name(), depManagement); found { // dependencyManagement from parent
		if dep.Version == "" {
			dep.Version = evaluateVariable(managed.Version, props, nil)
		}
		if dep.Scope == "" {
			dep.Scope = evaluateVariable(managed.Scope, props, nil)
		}
		// TODO: need to check the behavior
		if !dep.Optional {
			dep.Optional = managed.Optional
		}
		if len(dep.Exclusions.Exclusion) == 0 {
			dep.Exclusions = managed.Exclusions
		}
	}
	return dep
}

// ToArtifact converts dependency to artifact.
// It should be called after calling Resolve() so that variables can be evaluated.
func (d pomDependency) ToArtifact(opts analysisOptions) artifact {
	// To avoid shadow adding exclusions to top pom's,
	// we need to initialize a new map for each new artifact
	// See `exclusions in child` test for more information
	exclusions := make(map[string]struct{})
	if opts.exclusions != nil {
		exclusions = maps.Clone(opts.exclusions)
	}
	for _, e := range d.Exclusions.Exclusion {
		exclusions[fmt.Sprintf("%s:%s", e.GroupID, e.ArtifactID)] = struct{}{}
	}

	var locations types.Locations
	if opts.lineNumber {
		locations = types.Locations{
			{
				StartLine: d.StartLine,
				EndLine:   d.EndLine,
			},
		}
	}

	return artifact{
		GroupID:    d.GroupID,
		ArtifactID: d.ArtifactID,
		Version:    newVersion(d.Version),
		Exclusions: exclusions,
		Locations:  locations,
	}
}

type properties map[string]string

type property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (props *properties) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	*props = properties{}
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

func (deps *pomDependencies) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error {
	for {
		token, err := d.Token()
		if err == io.EOF {
			break
		} else if err != nil {
			return xerrors.Errorf("XML decode error: %w", err)
		}

		t, ok := token.(xml.StartElement)
		if !ok {
			continue
		}

		if t.Name.Local == "dependency" {
			var dep pomDependency
			dep.StartLine, _ = d.InputPos() // <dependency> tag starts

			// Decode the <dependency> element
			err = d.DecodeElement(&dep, &t)
			if err != nil {
				return xerrors.Errorf("Error decoding dependency: %w", err)
			}

			dep.EndLine, _ = d.InputPos() // <dependency> tag ends
			deps.Dependency = append(deps.Dependency, dep)
		}
	}
	return nil
}

func findDep(name string, depManagement []pomDependency) (pomDependency, bool) {
	return lo.Find(depManagement, func(item pomDependency) bool {
		return item.Name() == name
	})
}

type pomRepositories struct {
	Text       string          `xml:",chardata"`
	Repository []pomRepository `xml:"repository"`
}

type pomRepository struct {
	Text     string `xml:",chardata"`
	ID       string `xml:"id"`
	Name     string `xml:"name"`
	URL      string `xml:"url"`
	Releases struct {
		Text    string `xml:",chardata"`
		Enabled string `xml:"enabled"`
	} `xml:"releases"`
	Snapshots struct {
		Text    string `xml:",chardata"`
		Enabled string `xml:"enabled"`
	} `xml:"snapshots"`
}
