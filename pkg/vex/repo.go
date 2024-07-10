package vex

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
)

// RepositoryIndex wraps the repository index
type RepositoryIndex struct {
	Name string
	URL  string
	repo.Index
}

type RepositorySet struct {
	indexes []RepositoryIndex
	logger  *log.Logger
}

func NewRepositorySet(ctx context.Context, cacheDir string) (*RepositorySet, error) {
	conf, err := repo.NewManager(cacheDir).Config(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed to get VEX repository config: %w", err)
	}

	var indexes []RepositoryIndex
	for _, r := range conf.Repositories {
		index, err := r.Index(ctx)
		if err != nil {
			return nil, xerrors.Errorf("failed to get VEX repository index: %w", err)
		}
		indexes = append(indexes, RepositoryIndex{
			Name:  r.Name,
			URL:   r.URL,
			Index: index,
		})
	}
	return &RepositorySet{
		indexes: indexes, // In precedence order
		logger:  log.WithPrefix("vex"),
	}, nil
}

func (rs *RepositorySet) Filter(result *types.Result, bom *core.BOM) {
	filterVulnerabilities(result, bom, rs.NotAffected)
}

func (rs *RepositorySet) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {
	if product == nil || product.PkgIdentifier.PURL == nil {
		return types.ModifiedFinding{}, false
	}
	p := *product.PkgIdentifier.PURL
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""

	pkgID := p.String() // PURL without version, qualifiers, and subpath
	for _, index := range rs.indexes {
		entry, ok := index.Packages[pkgID]
		if !ok {
			continue
		}
		source := fmt.Sprintf("VEX Repository: %s (%s)", index.Name, index.URL)
		doc, err := rs.OpenDocument(source, filepath.Dir(index.Path), entry)
		if err != nil {
			log.Warn("Failed to open the VEX document", log.String("location", entry.Location), log.Err(err))
			return types.ModifiedFinding{}, false
		}

		if m, notAffected := doc.NotAffected(vuln, product, subComponent); notAffected {
			return m, notAffected
		}

		log.Debug("VEX found, but affected", log.String("vulnerability", vuln.VulnerabilityID),
			log.String("package", pkgID), log.String("repo", index.Name), log.String("repo_url", index.URL))
		break // Stop searching for the next VEX document as this repository has higher precedence.
	}
	return types.ModifiedFinding{}, false
}

func (rs *RepositorySet) OpenDocument(source, dir string, entry repo.PackageEntry) (VEX, error) {
	f, err := os.Open(filepath.Join(dir, entry.Location))
	if err != nil {
		return nil, xerrors.Errorf("failed to open the VEX document: %w", err)
	}
	defer f.Close()

	switch entry.Format {
	case "openvex", "":
		return decodeOpenVEX(f, source)
	case "csaf":
		return decodeCSAF(f)
	default:
		return nil, xerrors.Errorf("unsupported VEX format: %s", entry.Format)
	}
}
