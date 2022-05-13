package k8s

import (
	"context"
	"errors"
	"io"

	"github.com/cheggaaa/pb/v3"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// Run runs scan on kubernetes cluster
func Run(cliCtx *cli.Context) error {
	opt, err := cmd.InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	ctx, cancel := context.WithTimeout(cliCtx.Context, opt.Timeout)
	defer cancel()

	defer func() {
		if xerrors.Is(err, context.DeadlineExceeded) {
			log.Logger.Warn("Increase --timeout value")
		}
	}()

	runner, err := cmd.NewRunner(opt)
	if err != nil {
		if errors.Is(err, cmd.SkipScan) {
			return nil
		}
		return xerrors.Errorf("init error: %w", err)
	}
	defer runner.Close()

	cluster, err := k8s.GetCluster()
	if err != nil {
		return xerrors.Errorf("get k8s cluster: %w", err)
	}

	trivyk8s := trivyk8s.New(cluster).Namespace(opt.KubernetesOption.Namespace)

	// list all kubernetes scannable artifacts
	artifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	report, err := run(ctx, runner, opt, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	report.ClusterName = cluster.GetCurrentContext()

	if err = write(report, pkgReport.Option{
		Format: opt.KubernetesOption.ReportFormat, // for now json is the default
		Output: opt.Output,
	}, opt.Severities); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	cmd.Exit(opt, report.Failed())

	return nil
}

func run(ctx context.Context, runner *cmd.Runner, opt cmd.Option, artifacts []*artifacts.Artifact) (Report, error) {
	opt.SecurityChecks = []string{types.SecurityCheckVulnerability, types.SecurityCheckConfig}

	// progress bar
	bar := pb.StartNew(len(artifacts))
	if opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	vulns := make([]Resource, 0)
	misconfigs := make([]Resource, 0)

	// disable logs before scanning
	err := log.InitLogger(opt.Debug, true)
	if err != nil {
		return Report{}, xerrors.Errorf("logger error: %w", err)
	}

	// Loops once over all artifacts, and execute scanners as necessary. Not every artifacts has an image,
	// so image scanner is not always executed.
	for _, artifact := range artifacts {
		bar.Increment()

		// scan images if present
		for _, image := range artifact.Images {
			opt.Target = image
			imageReport, err := runner.ScanImage(ctx, opt)
			if err != nil {
				// add error to report
				log.Logger.Debugf("failed to scan image %s: %s", image, err)
				vulns = append(vulns, createResource(artifact, imageReport, err))
				continue
			}

			imageReport, err = runner.Filter(ctx, opt, imageReport)
			if err != nil {
				return Report{}, xerrors.Errorf("filter error: %w", err)
			}

			vulns = append(vulns, createResource(artifact, imageReport, nil))
		}

		// scan configurations
		configFile, err := createTempFile(artifact)
		if err != nil {
			return Report{}, xerrors.Errorf("scan error: %w", err)
		}

		opt.Target = configFile
		configReport, err := runner.ScanFilesystem(ctx, opt)
		removeFile(configFile)
		if err != nil {
			// add error to report
			log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
			misconfigs = append(misconfigs, createResource(artifact, configReport, err))
		}

		configReport, err = runner.Filter(ctx, opt, configReport)
		if err != nil {
			return Report{}, xerrors.Errorf("filter error: %w", err)
		}

		misconfigs = append(misconfigs, createResource(artifact, configReport, nil))
	}

	// enable logs after scanning
	err = log.InitLogger(opt.Debug, opt.Quiet)
	if err != nil {
		return Report{}, xerrors.Errorf("logger error: %w", err)
	}

	return Report{
		SchemaVersion:     0,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}
