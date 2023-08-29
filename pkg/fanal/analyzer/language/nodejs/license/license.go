package license

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type License struct {
	parser                    *packagejson.Parser
	classifierConfidenceLevel float64
}

func NewLicense(classifierConfidenceLevel float64) *License {
	return &License{
		parser:                    packagejson.NewParser(),
		classifierConfidenceLevel: classifierConfidenceLevel,
	}
}

func (l *License) Traverse(fsys fs.FS, root string) (map[string][]string, error) {
	licenses := map[string][]string{}
	walkDirFunc := func(pkgJSONPath string, d fs.DirEntry, r io.Reader) error {
		pkg, err := l.parser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", pkgJSONPath, err)
		}

		ok, licenseFileName := IsLicenseRefToFile(pkg.License)
		if !ok {
			licenses[pkg.ID] = []string{pkg.License}
			return nil
		}

		log.Logger.Debugf("License names are missing in %q, an attempt to find them in the %q file", pkgJSONPath, licenseFileName)
		licenseFilePath := path.Join(path.Dir(pkgJSONPath), licenseFileName)

		if findings, err := classifyLicense(licenseFilePath, l.classifierConfidenceLevel, fsys); err != nil {
			return xerrors.Errorf("unable to classify the license: %w", err)
		} else if len(findings) > 0 {
			// License found
			licenses[pkg.ID] = findings.Names()
		} else {
			log.Logger.Debugf("The license file %q was not found or the license could not be classified", licenseFilePath)
		}
		return nil
	}
	if err := fsutils.WalkDir(fsys, root, fsutils.RequiredFile(types.NpmPkg), walkDirFunc); err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return licenses, nil
}

// IsLicenseRefToFile The license field can refer to a file
// https://docs.npmjs.com/cli/v9/configuring-npm/package-json
func IsLicenseRefToFile(maybeLicense string) (bool, string) {
	if maybeLicense == "" {
		// trying to find at least the LICENSE file
		return true, "LICENSE"
	}

	var licenseFileName string
	if strings.HasPrefix(maybeLicense, "LicenseRef-") {
		// LicenseRef-<filename>
		licenseFileName = strings.Split(maybeLicense, "-")[1]
	} else if strings.HasPrefix(maybeLicense, "SEE LICENSE IN ") {
		// SEE LICENSE IN <filename>
		parts := strings.Split(maybeLicense, " ")
		licenseFileName = parts[len(parts)-1]
	}

	return licenseFileName != "", licenseFileName
}

func classifyLicense(filePath string, classifierConfidenceLevel float64, fsys fs.FS) (types.LicenseFindings, error) {
	f, err := fsys.Open(filePath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	l, err := licensing.Classify(filePath, f, classifierConfidenceLevel)
	if err != nil {
		return nil, xerrors.Errorf("license classify error: %w", err)
	}

	if l == nil {
		return nil, nil
	}

	return l.Findings, nil
}
