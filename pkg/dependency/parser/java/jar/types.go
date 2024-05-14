package jar

import (
	"errors"
	"fmt"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var ArtifactNotFoundErr = errors.New("no artifact found")

type Properties struct {
	GroupID    string
	ArtifactID string
	Version    string
	FilePath   string // path to file containing these props
}

func (p Properties) Package() ftypes.Package {
	return ftypes.Package{
		Name:     fmt.Sprintf("%s:%s", p.GroupID, p.ArtifactID),
		Version:  p.Version,
		FilePath: p.FilePath,
	}
}

func (p Properties) Valid() bool {
	return p.GroupID != "" && p.ArtifactID != "" && p.Version != ""
}

func (p Properties) String() string {
	return fmt.Sprintf("%s:%s:%s", p.GroupID, p.ArtifactID, p.Version)
}
