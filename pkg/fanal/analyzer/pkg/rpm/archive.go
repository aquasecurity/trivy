package rpm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/sassoftware/go-rpmutils"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
)

const archiveVersion = 1

func init() {
	analyzer.RegisterAnalyzer(newRPMArchiveAnalyzer())
}

type rpmArchiveAnalyzer struct {
	logger *log.Logger
}

func newRPMArchiveAnalyzer() *rpmArchiveAnalyzer {
	return &rpmArchiveAnalyzer{
		logger: log.WithPrefix("rpm-archive"),
	}
}

func (a *rpmArchiveAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	rpm, err := rpmutils.ReadRpm(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("failed to read rpm (%s): %w", input.FilePath, err)
	}
	pkg, err := a.parseHeader(rpm.Header)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse rpm header: %w", err)
	}
	pkg.FilePath = input.FilePath
	pkg.Identifier.PURL = a.generatePURL(&pkg)

	return &analyzer.AnalysisResult{
		PackageInfos: []types.PackageInfo{
			{
				FilePath: input.FilePath,
				Packages: types.Packages{pkg},
			},
		},
	}, nil
}

func (a *rpmArchiveAnalyzer) parseHeader(h *rpmutils.RpmHeader) (types.Package, error) {
	if h == nil {
		return types.Package{}, errors.New("rpm header is nil")
	}
	// Getting metadata
	nevra, err := h.GetNEVRA()
	if a.unexpectedError(err) != nil {
		return types.Package{}, xerrors.Errorf("failed to get NEVRA: %w", err)
	}
	epoch, err := strconv.Atoi(nevra.Epoch)
	if a.unexpectedError(err) != nil {
		return types.Package{}, xerrors.Errorf("failed to convert epoch to int (%s): %w", nevra.Name, err)
	}
	licenses, err := h.GetStrings(rpmutils.LICENSE)
	if a.unexpectedError(err) != nil {
		return types.Package{}, xerrors.Errorf("failed to get licenses: %w", err)
	}
	srcName, srcVer, srcRel, err := a.parseSourceRPM(h)
	if err != nil {
		return types.Package{}, xerrors.Errorf("failed to parse source rpm: %w", err)
	}
	vendor, err := h.GetString(rpmutils.VENDOR)
	if a.unexpectedError(err) != nil {
		return types.Package{}, xerrors.Errorf("failed to get vendor: %w", err)
	}

	// TODO: add the const to go-rpmutils
	// cf. https://github.com/rpm-software-management/rpm/blob/rpm-4.16.0-release/lib/rpmtag.h#L375
	const modularityLabelTag = 5096
	modularityLabel, err := h.GetString(modularityLabelTag)
	if a.unexpectedError(err) != nil {
		return types.Package{}, xerrors.Errorf("failed to get modularitylabel: %w", err)
	}

	return types.Package{
		Name:            nevra.Name,
		Version:         nevra.Version,
		Release:         nevra.Release,
		Epoch:           epoch,
		Arch:            nevra.Arch,
		SrcName:         srcName,
		SrcVersion:      srcVer,
		SrcRelease:      srcRel,
		SrcEpoch:        epoch,
		Licenses:        licenses,
		Maintainer:      vendor,
		Modularitylabel: modularityLabel,
	}, nil
}

func (a *rpmArchiveAnalyzer) parseSourceRPM(h *rpmutils.RpmHeader) (string, string, string, error) {
	sourceRpm, err := h.GetString(rpmutils.SOURCERPM)
	if a.unexpectedError(err) != nil {
		return "", "", "", xerrors.Errorf("failed to get source rpm: %w", err)
	} else if sourceRpm == "(none)" || sourceRpm == "" {
		return "", "", "", nil
	}

	srcName, srcVer, srcRel, err := splitFileName(sourceRpm)
	if err != nil {
		a.logger.Debug("Invalid Source RPM Found", log.String("sourcerpm", sourceRpm))
	}
	return srcName, srcVer, srcRel, nil
}

func (a *rpmArchiveAnalyzer) generatePURL(pkg *types.Package) *packageurl.PackageURL {
	vendor := strings.ToLower(pkg.Maintainer)

	// TODO: Handle more vendors
	var ns string
	switch {
	case strings.Contains(vendor, "red hat"):
		ns = "redhat"
	case strings.Contains(vendor, "fedora"):
		ns = "fedora"
	case strings.Contains(vendor, "opensuse"):
		ns = "opensuse"
	case strings.Contains(vendor, "suse"):
		ns = "suse"
	}
	var qualifiers packageurl.Qualifiers
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	return packageurl.NewPackageURL(packageurl.TypeRPM, ns, pkg.Name, utils.FormatVersion(*pkg), qualifiers, "")
}

func (a *rpmArchiveAnalyzer) unexpectedError(err error) error {
	var rerr rpmutils.NoSuchTagError
	if errors.As(err, &rerr) {
		a.logger.Debug("RPM tag not found", log.Err(rerr))
		return nil
	}
	return err
}

func (a *rpmArchiveAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Ext(filePath) == ".rpm"
}

func (a *rpmArchiveAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRpmArchive
}

func (a *rpmArchiveAnalyzer) Version() int {
	return archiveVersion
}
