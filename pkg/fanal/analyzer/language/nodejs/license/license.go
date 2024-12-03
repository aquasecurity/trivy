package license

import (
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type License struct {
	logger                    *log.Logger
	parser                    *packagejson.Parser
	classifierConfidenceLevel float64
}

func NewLicense(classifierConfidenceLevel float64) *License {
	return &License{
		logger:                    log.WithPrefix("npm"),
		parser:                    packagejson.NewParser(),
		classifierConfidenceLevel: classifierConfidenceLevel,
	}
}

func (l *License) Traverse(fsys fs.FS, root string) (map[string][]string, error) {
	licenses := make(map[string][]string)
	walkDirFunc := func(pkgJSONPath string, d fs.DirEntry, r io.Reader) error {
		pkg, err := l.parser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", pkgJSONPath, err)
		}

		ok, licenseFileName := IsLicenseRefToFile(pkg.Licenses)
		if !ok {
			licenses[pkg.ID] = pkg.Licenses
			return nil
		}

		l.logger.Debug("License names are missing, an attempt to find them in the license file",
			log.FilePath(pkgJSONPath), log.String("license_file", licenseFileName))
		licenseFilePath := path.Join(path.Dir(pkgJSONPath), licenseFileName)

		if findings, err := classifyLicense(licenseFilePath, l.classifierConfidenceLevel, fsys); err != nil {
			return xerrors.Errorf("unable to classify the license: %w", err)
		} else if len(findings) > 0 {
			// License found
			licenses[pkg.ID] = findings.Names()
		} else {
			l.logger.Debug("The license file was not found or the license could not be classified",
				log.String("license_file", licenseFilePath))
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
func IsLicenseRefToFile(maybeLicenses []string) (bool, string) {
	if len(maybeLicenses) != 1 {
		// trying to find at least the LICENSE file
		return true, "LICENSE"
	}

	var licenseFileName string
	if strings.HasPrefix(maybeLicenses[0], "LicenseRef-") {
		// LicenseRef-<filename>
		licenseFileName = strings.Split(maybeLicenses[0], "-")[1]
	} else if strings.HasPrefix(maybeLicenses[0], "SEE LICENSE IN ") {
		// SEE LICENSE IN <filename>
		parts := strings.Split(maybeLicenses[0], " ")
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
