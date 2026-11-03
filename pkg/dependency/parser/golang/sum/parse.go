package sum

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"strings"

	"golang.org/x/mod/module"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses a go.sum file
func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var pkgs []ftypes.Package
	uniquePkgs := make(map[string]string)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		s := strings.Fields(line)
		if len(s) < 2 {
			continue
		}

		// go.sum records and sorts all non-major versions
		// with the latest version as last entry
		uniquePkgs[s[0]] = strings.TrimSuffix(s[1], "/go.mod")
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, xerrors.Errorf("scan error: %w", err)
	}

	for k, v := range uniquePkgs {
		pkgs = append(pkgs, ftypes.Package{
			ID:      dependency.ID(ftypes.GoModule, k, v),
			Name:    k,
			Version: v,
		})
	}

	return pkgs, nil, nil
}

// ParseDigests returns the h1 checksums of whole modules recorded in a go.sum file,
// decoded to SHA-256 digests and keyed by module path and version.
func ParseDigests(r io.Reader) (map[module.Version]digest.Digest, error) {
	digests := make(map[module.Version]digest.Digest)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		s := strings.Fields(scanner.Text())
		if len(s) < 3 {
			continue
		}

		// A /go.mod entry covers only the go.mod file, not the whole module.
		if strings.HasSuffix(s[1], "/go.mod") {
			continue
		}

		h, ok := strings.CutPrefix(s[2], "h1:")
		if !ok {
			continue
		}

		b, err := base64.StdEncoding.DecodeString(h)
		if err != nil || len(b) != sha256.Size {
			continue
		}

		d := digest.NewDigestFromString(digest.SHA256, hex.EncodeToString(b))
		digests[module.Version{Path: s[0], Version: s[1]}] = d
	}

	if err := scanner.Err(); err != nil {
		return nil, xerrors.Errorf("scan error: %w", err)
	}

	return digests, nil
}
