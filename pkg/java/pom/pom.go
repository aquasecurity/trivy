package pom

import (
	"encoding/xml"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/samber/lo"

	"github.com/aquasecurity/go-dep-parser/pkg/utils"
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
	p.content.Version = art.Version.String()
}

func (p pom) properties() properties {
	props := p.content.Properties
	return utils.MergeMaps(props, p.projectProperties())
}

func (p pom) projectProperties() map[string]string {
	val := reflect.ValueOf(p.content).Elem()
	props := p.listProperties(val)

	// https://maven.apache.org/pom.html#properties
	projectProperties := map[string]string{}
	for k, v := range props {
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
	props := map[string]string{}
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
	return newArtifact(p.content.GroupId, p.content.ArtifactId, p.content.Version, p.content.Properties)
}

func (p pom) repositories() []string {
	var urls []string
	for _, rep := range p.content.Repositories.Repository {
		if rep.Releases.Enabled != "false" {
			urls = append(urls, rep.URL)
		}
	}
	return urls
}

type pomXML struct {
	Parent     pomParent `xml:"parent"`
	GroupId    string    `xml:"groupId"`
	ArtifactId string    `xml:"artifactId"`
	Version    string    `xml:"version"`
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
	Repositories struct {
		Text       string `xml:",chardata"`
		Repository []struct {
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
		} `xml:"repository"`
	} `xml:"repositories"`
}

type pomParent struct {
	GroupId      string `xml:"groupId"`
	ArtifactId   string `xml:"artifactId"`
	Version      string `xml:"version"`
	RelativePath string `xml:"relativePath"`
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
func (d pomDependency) ToArtifact(exclusions map[string]struct{}) artifact {
	if exclusions == nil {
		exclusions = map[string]struct{}{}
	}
	for _, e := range d.Exclusions.Exclusion {
		exclusions[fmt.Sprintf("%s:%s", e.GroupID, e.ArtifactID)] = struct{}{}
	}
	return artifact{
		GroupID:    d.GroupID,
		ArtifactID: d.ArtifactID,
		Version:    newVersion(d.Version),
		Exclusions: exclusions,
	}
}

type properties map[string]string

type property struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

func (props *properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*props = properties{}
	for {
		var p property
		err := d.Decode(&p)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		(*props)[p.XMLName.Local] = p.Value
	}
	return nil
}

func findDep(name string, depManagement []pomDependency) (pomDependency, bool) {
	return lo.Find(depManagement, func(item pomDependency) bool {
		return item.Name() == name
	})
}
