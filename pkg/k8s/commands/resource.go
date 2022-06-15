package commands

import (
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
)

// resourceRun runs scan on kubernetes cluster
func resourceRun(cliCtx *cli.Context, opt cmd.Option, cluster k8s.Cluster) error {
	kind, name, err := extractKindAndName(cliCtx.Args().Slice())
	if err != nil {
		return err
	}

	trivyk8s := trivyk8s.New(cluster, log.Logger).Namespace(getNamespace(opt, cluster.GetCurrentNamespace()))

	artifact, err := trivyk8s.GetArtifact(cliCtx.Context, kind, name)
	if err != nil {
		return err
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), []*artifacts.Artifact{artifact})
}

func extractKindAndName(args []string) (string, string, error) {
	switch len(args) {
	case 1:
		s := strings.Split(args[0], "/")
		if len(s) != 2 {
			return "", "", xerrors.Errorf("can't parse arguments %v. Please run `trivy k8s` for usage.", args)
		}

		return s[0], s[1], nil
	case 2:
		return args[0], args[1], nil
	}

	return "", "", xerrors.Errorf("can't parse arguments %v. Please run `trivy k8s` for usage.", args)
}
