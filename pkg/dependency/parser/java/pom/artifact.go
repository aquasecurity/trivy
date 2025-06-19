package pom

import (
	"fmt"
	"strings"
	"sync"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/version/doc"
)

var (
	emptyVersionWarn = sync.OnceFunc(func() {
		log.WithPrefix("pom").Warn("Dependency version cannot be determined. Child dependencies will not be found.",
			// e.g. https://trivy.dev/latest/docs/coverage/language/java/#empty-dependency-version
			log.String("details", doc.URL("/docs/coverage/language/java/", "empty-dependency-version")))
	})
)

type artifact struct {
	GroupID    string
	ArtifactID string
	Version    version
	Licenses   []string

	Exclusions set.Set[string]

	Module       bool
	Relationship ftypes.Relationship

	Locations ftypes.Locations
}

func newArtifact(groupID, artifactID, version string, licenses []string, props map[string]string) artifact {
	return artifact{
		GroupID:      evaluateVariable(groupID, props, nil),
		ArtifactID:   evaluateVariable(artifactID, props, nil),
		Version:      newVersion(evaluateVariable(version, props, nil)),
		Licenses:     licenses,
		Relationship: ftypes.RelationshipIndirect, // default
	}
}

func (a artifact) IsEmpty() bool {
	if a.GroupID == "" || a.ArtifactID == "" {
		return true
	}
	if a.Version.String() == "" {
		emptyVersionWarn()
		log.WithPrefix("pom").Debug("Dependency version cannot be determined.",
			log.String("GroupID", a.GroupID),
			log.String("ArtifactID", a.ArtifactID),
		)
	}
	return false
}

func (a artifact) Equal(o artifact) bool {
	return a.GroupID == o.GroupID || a.ArtifactID == o.ArtifactID || a.Version.String() == o.Version.String()
}

func (a artifact) ToPOMLicenses() pomLicenses {
	return pomLicenses{
		License: lo.Map(a.Licenses, func(lic string, _ int) pomLicense {
			return pomLicense{Name: lic}
		}),
	}
}

func (a artifact) Inherit(parent artifact) artifact {
	// inherited from a parent
	if a.GroupID == "" {
		a.GroupID = parent.GroupID
	}

	if len(a.Licenses) == 0 {
		a.Licenses = parent.Licenses
	}

	if a.Version.String() == "" {
		a.Version = parent.Version
	}
	return a
}

func (a artifact) Name() string {
	return fmt.Sprintf("%s:%s", a.GroupID, a.ArtifactID)
}

func (a artifact) String() string {
	return fmt.Sprintf("%s:%s", a.Name(), a.Version)
}

type version struct {
	ver  string
	hard bool
}

// Only soft and hard requirements for the specified version are supported at the moment.
func newVersion(s string) version {
	var hard bool
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		s = strings.Trim(s, "[]")
		hard = true
	}

	// TODO: Other requirements are not supported
	if strings.ContainsAny(s, ",()[]") {
		s = ""
	}

	return version{
		ver:  s,
		hard: hard,
	}
}

func (v1 version) shouldOverride(v2 version) bool {
	if !v1.hard && v2.hard {
		return true
	}
	return false
}

func (v1 version) String() string {
	return v1.ver
}

func printLoopedPropertiesStack(env string, usedProps []string) {
	var s string
	for _, prop := range usedProps {
		s += fmt.Sprintf("%s -> ", prop)
	}
	log.Warn("Lopped properties were detected", log.String("prop", s+env))
}
