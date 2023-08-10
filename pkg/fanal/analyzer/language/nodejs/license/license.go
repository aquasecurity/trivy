package nodejs

import (
	"errors"
	"io/fs"
	"path"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func ParseLicenses(
	packageJsonParser *packagejson.Parser,
	classifierConfidenceLevel float64,
	licenses map[string][]string,
) func(fsys fs.FS, root string) error {
	return func(fsys fs.FS, root string) error {
		if fsys == nil {
			return xerrors.New("fs.FS required")
		}

		walkDirFunc := func(pkgJsonPath string, d fs.DirEntry, r dio.ReadSeekerAt) error {

			pkg, err := packageJsonParser.Parse(r)
			if err != nil {
				return xerrors.Errorf("unable to parse %q: %w", pkgJsonPath, err)
			}

			ok, licenseFileName := isLicenseRefToFile(pkg.License)

			if !ok {
				licenses[pkg.ID] = []string{pkg.License}
				return nil
			}

			log.Logger.Debugf("Licenses are missing in %q, an attempt to find them in the LICENSE file", pkgJsonPath)
			licenseFilePath := path.Join(path.Dir(pkgJsonPath), licenseFileName)

			findings, err := classifyLicense(licenseFilePath, classifierConfidenceLevel, fsys)
			if err != nil {
				return err
			}

			// License found
			if len(findings) > 0 {
				licenses[pkg.ID] = findings.Names()
			} else {
				log.Logger.Debugf("The license file %q was not found or the license could not be classified", licenseFilePath)
			}
			return nil
		}

		if err := fsutils.WalkDir(fsys, root, isNodeModulesPkg, walkDirFunc); err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}

		return nil
	}
}

// isLicenseRefToFile The license field can refer to a file
// https://docs.npmjs.com/cli/v9/configuring-npm/package-json
func isLicenseRefToFile(maybeLicense string) (bool, string) {
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
