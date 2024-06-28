package convert

import (
	"context"
	"encoding/json"
	"os"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/types"
)

func Run(ctx context.Context, opts flag.Options) (err error) {
	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	f, err := os.Open(opts.Target)
	if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var r types.Report
	if err = json.NewDecoder(f).Decode(&r); err != nil {
		return xerrors.Errorf("json decode error: %w", err)
	}

	// "convert" supports JSON results produced by Trivy scanning other than AWS and Kubernetes
	if r.ArtifactName == "" && r.ArtifactType == "" {
		return xerrors.New("AWS and Kubernetes scanning reports are not yet supported")
	}

	compat(&r)
	if err = result.Filter(ctx, r, opts.FilterOpts()); err != nil {
		return xerrors.Errorf("unable to filter results: %w", err)
	}

	log.Debug("Writing report to output...")
	if err = report.Write(ctx, r, opts); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	return operation.Exit(opts, r.Results.Failed(), r.Metadata)
}

// compat converts the JSON report to the latest format
func compat(r *types.Report) {
	for i, res := range r.Results {
		pkgs := make(map[string]ftypes.Package, len(res.Packages))
		for j, pkg := range res.Packages {
			if pkg.Identifier.UID != "" {
				continue
			}
			// Fill in the UID field since older JSON reports don't have it
			pkg.Identifier.UID = dependency.UID(res.Target, pkg)
			pkgs[pkg.ID+pkg.FilePath] = pkg
			r.Results[i].Packages[j] = pkg
		}

		for j, vuln := range res.Vulnerabilities {
			if vuln.PkgIdentifier.UID != "" {
				continue
			}
			if pkg, ok := pkgs[vuln.PkgID+vuln.PkgPath]; !ok {
				continue
			} else {
				r.Results[i].Vulnerabilities[j].PkgIdentifier = pkg.Identifier
			}
		}
	}
}
