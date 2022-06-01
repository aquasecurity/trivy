package commands

import (
	"os"
	"strings"

	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// ResourceRun runs scan on kubernetes cluster
func ResourceRun(cliCtx *cli.Context) error {
	if cliCtx.String("input") == "" && cliCtx.Args().Len() == 0 {
		_ = cli.ShowSubcommandHelp(cliCtx) // nolint: errcheck
		os.Exit(0)
	}

	opt, err := InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	cluster, err := k8s.GetCluster(opt.KubernetesOption.ClusterContext)
	if err != nil {
		return xerrors.Errorf("get k8s cluster: %w", err)
	}

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
