package spec

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-checks/pkg/specs"
	compliance "github.com/aquasecurity/trivy/pkg/compliance/types"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/log"
)

const (
	FailStatus iacTypes.ControlStatus = "FAIL"
	PassStatus iacTypes.ControlStatus = "PASS"
	WarnStatus iacTypes.ControlStatus = "WARN"
)

func checksDir(cacheDir string) string {
	return filepath.Join(cacheDir, "policy")
}

func complianceSpecDir(cacheDir string) string {
	return filepath.Join(checksDir(cacheDir), "content", "specs", "compliance")
}

// GetComplianceSpec accepct compliance flag name/path and return builtin or file system loaded spec
func GetComplianceSpec(specNameOrPath, cacheDir string) (compliance.Spec, error) {
	if specNameOrPath == "" {
		return compliance.Spec{}, nil
	}

	var b []byte
	var err error
	if after, ok := strings.CutPrefix(specNameOrPath, "@"); ok { // load user specified spec from disk
		b, err = os.ReadFile(after)
		if err != nil {
			return compliance.Spec{}, fmt.Errorf("error retrieving compliance spec from path: %w", err)
		}
		log.Debug("Compliance spec loaded from specified path", log.String("path", specNameOrPath))
	} else {
		_, err := os.Stat(filepath.Join(checksDir(cacheDir), "metadata.json"))
		if err != nil { // cache corrupt or bundle does not exist, load embedded version
			b = []byte(specs.GetSpec(specNameOrPath))
			log.Debug("Compliance spec loaded from embedded library", log.String("spec", specNameOrPath))
		} else {
			// load from bundle on disk
			b, err = loadFromBundle(cacheDir, specNameOrPath)
			if err != nil {
				return compliance.Spec{}, err
			}
			log.Debug("Compliance spec loaded from disk bundle", log.String("spec", specNameOrPath))
		}
	}

	var complianceSpec compliance.Spec
	if err = yaml.Unmarshal(b, &complianceSpec); err != nil {
		return compliance.Spec{}, xerrors.Errorf("spec yaml decode error: %w", err)
	}
	return complianceSpec, nil

}

func loadFromBundle(cacheDir, specNameOrPath string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(complianceSpecDir(cacheDir), specNameOrPath+".yaml"))
	if err != nil {
		return nil, fmt.Errorf("error retrieving compliance spec from bundle %s: %w", specNameOrPath, err)
	}
	return b, nil
}
