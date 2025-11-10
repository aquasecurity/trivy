package vex

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/vex/repo"
	xsync "github.com/aquasecurity/trivy/pkg/x/sync"
)

var errNoRepository = errors.New("no available VEX repository found")

// RepositoryIndex wraps the repository index
type RepositoryIndex struct {
	Name string
	URL  string
	repo.Index
}

type RepositorySet struct {
	indexes []RepositoryIndex
	logOnce *xsync.Map[string, *sync.Once]
	logger  *log.Logger
}

func NewRepositorySet(ctx context.Context, cacheDir string) (*RepositorySet, error) {
	conf, err := repo.NewManager(cacheDir).Config(ctx)
	if err != nil {
		return nil, xerrors.Errorf("failed to get VEX repository config: %w", err)
	}

	logger := log.WithPrefix("vex")
	var indexes []RepositoryIndex
	for _, r := range conf.EnabledRepositories() {
		index, err := r.Index(ctx)
		if errors.Is(err, os.ErrNotExist) {
			logger.Warn("VEX repository not found locally, skipping this repository", log.String("repo", r.Name))
			continue
		} else if err != nil {
			return nil, xerrors.Errorf("failed to get VEX repository index: %w", err)
		}
		indexes = append(indexes, RepositoryIndex{
			Name:  r.Name,
			URL:   r.URL,
			Index: index,
		})
	}
	if len(indexes) == 0 {
		logger.Warn("No available VEX repository found locally")
		return nil, errNoRepository
	}

	return &RepositorySet{
		indexes: indexes, // In precedence order
		logOnce: new(xsync.Map[string, *sync.Once]),
		logger:  logger,
	}, nil
}

func (rs *RepositorySet) NotAffected(vuln types.DetectedVulnerability, product, subComponent *core.Component) (types.ModifiedFinding, bool) {
	if product == nil || product.PkgIdentifier.PURL == nil {
		return types.ModifiedFinding{}, false
	}
	p := *product.PkgIdentifier.PURL

	// Exclude version, qualifiers, and subpath from the package URL except for OCI
	// cf. https://github.com/aquasecurity/vex-repo-spec?tab=readme-ov-file#32-indexjson
	p.Version = ""
	p.Qualifiers = nil
	p.Subpath = ""

	if p.Type == packageurl.TypeOCI {
		// For OCI artifacts, we consider "repository_url" is part of name.
		for _, q := range product.PkgIdentifier.PURL.Qualifiers {
			if q.Key == "repository_url" {
				p.Qualifiers = packageurl.Qualifiers{q}
				break
			}
		}
	}

	pkgID := p.String() // PURL without version, qualifiers, and subpath
	for _, index := range rs.indexes {
		entry, ok := index.Packages[pkgID]
		if !ok {
			continue
		}
		rs.logVEXFound(pkgID, index.Name, index.URL, entry.Location)

		source := fmt.Sprintf("VEX Repository: %s (%s)", index.Name, index.URL)
		doc, err := rs.OpenDocument(source, filepath.Dir(index.Path), entry)
		if err != nil {
			rs.logger.Warn("Failed to open the VEX document", log.String("location", entry.Location), log.Err(err))
			return types.ModifiedFinding{}, false
		}

		if m, notAffected := doc.NotAffected(vuln, product, subComponent); notAffected {
			return m, notAffected
		}

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
		return decodeCSAF(f, source)
	default:
		return nil, xerrors.Errorf("unsupported VEX format: %s", entry.Format)
	}
}

func (rs *RepositorySet) logVEXFound(pkgID, repoName, repoURL, filePath string) {
	once, _ := rs.logOnce.LoadOrStore(pkgID, &sync.Once{})
	once.Do(func() {
		rs.logger.Debug("VEX found in the repository",
			log.String("package", pkgID),
			log.String("repo", repoName),
			log.String("repo_url", repoURL),
			log.FilePath(filePath),
		)
	})
}
