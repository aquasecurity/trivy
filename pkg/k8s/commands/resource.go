package commands

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
)

// resourceRun runs scan on kubernetes cluster
func resourceRun(ctx context.Context, args []string, opts flag.Options, cluster k8s.Cluster) error {
	kind, name, err := extractKindAndName(args)
	if err != nil {
		return err
	}

	runner := newRunner(opts, cluster.GetCurrentContext())

	var trivyk trivyk8s.TrivyK8S

	trivyk = trivyk8s.New(cluster, log.Logger, trivyk8s.WithExcludeOwned(opts.ExcludeOwned))

	if opts.AllNamespaces {
		trivyk = trivyk.AllNamespaces()
	} else {
		trivyk = trivyk.Namespace(getNamespace(opts, cluster.GetCurrentNamespace()))
	}

	if len(name) == 0 { // pods or configmaps etc
		if err = validateReportArguments(opts); err != nil {
			return err
		}

		targets, err := trivyk.Resources(kind).ListArtifacts(ctx)
		if err != nil {
			return err
		}

		return runner.run(ctx, targets)
	}

	// pod/NAME or pod NAME etc
	artifact, err := trivyk.GetArtifact(ctx, kind, name)
	if err != nil {
		return err
	}

	return runner.run(ctx, []*artifacts.Artifact{artifact})
}

func extractKindAndName(args []string) (string, string, error) {
	switch len(args) {
	case 1:
		s := strings.Split(args[0], "/")
		if len(s) != 2 {
			return args[0], "", nil
		}

		return s[0], s[1], nil
	case 2:
		return args[0], args[1], nil
	}

	return "", "", xerrors.Errorf("can't parse arguments %v. Please run `trivy k8s` for usage.", args)
}
