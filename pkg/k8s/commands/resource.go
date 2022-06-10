package commands

import (
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
)

// resourceRun runs scan on kubernetes cluster
func resourceRun(cliCtx *cli.Context, opt cmd.Option, cluster k8s.Cluster) error {
	kind, name, err := extractKindAndName(cliCtx.Args())
	if err != nil {
		return err
	}

	trivyk8s := trivyk8s.New(cluster).Namespace(getNamespace(cluster, opt))

	artifact, err := trivyk8s.GetArtifact(cliCtx.Context, kind, name)
	if err != nil {
		return err
	}

	return run(cliCtx.Context, opt, cluster.GetCurrentContext(), []*artifacts.Artifact{artifact})
}

func extractKindAndName(args cli.Args) (string, string, error) {
	switch args.Len() {
	case 1:
		s := strings.Split(args.Get(0), "/")
		if len(s) != 2 {
			return "", "", xerrors.Errorf("can't parse arguments: %v", args.Slice())
		}

		return s[0], s[1], nil
	case 2:
		return args.Get(0), args.Get(1), nil
	}

	return "", "", xerrors.Errorf("can't parse arguments: %v", args.Slice())
}
