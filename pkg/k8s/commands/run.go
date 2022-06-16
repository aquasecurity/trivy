package commands

import (
	"context"
	"errors"

	"github.com/aquasecurity/trivy/pkg/commands/option"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/urfave/cli/v2"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/k8s/report"
	"github.com/aquasecurity/trivy/pkg/k8s/scanner"
	"github.com/aquasecurity/trivy/pkg/log"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
)

const (
	clusterArtifact = "cluster"
	allArtifact     = "all"
)

// Run runs a k8s scan
func Run(cliCtx *cli.Context) error {
	opt, err := cmd.InitOption(cliCtx)
	if err != nil {
		return xerrors.Errorf("option error: %w", err)
	}

	cluster, err := k8s.GetCluster(opt.KubernetesOption.ClusterContext)
	if err != nil {
		return xerrors.Errorf("failed getting k8s cluster: %w", err)
	}

	switch cliCtx.Args().Get(0) {
	case clusterArtifact:
		return clusterRun(cliCtx, opt, cluster)
	case allArtifact:
		return namespaceRun(cliCtx, opt, cluster)
	default: // resourceArtifact
		return resourceRun(cliCtx, opt, cluster)
	}
}

func run(ctx context.Context, opt cmd.Option, cluster string, artifacts []*artifacts.Artifact) error {
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	var err error
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
	defer func() {
		if err := runner.Close(ctx); err != nil {
			log.Logger.Errorf("failed to close runner: %s", err)
		}
	}()

	s := scanner.NewScanner(cluster, runner, opt)

	r, err := s.Scan(ctx, artifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	workloadReport, rbacReport := separateMisConfigRoleAssessment(r, opt.ReportOption)

	if err := report.Write(workloadReport, report.Option{
		Format:        opt.Format,
		Report:        opt.KubernetesOption.ReportFormat,
		Output:        opt.Output,
		Severities:    opt.Severities,
		ColumnHeading: report.ColumnHeading(opt.ReportOption, report.WorkloadColumns()),
	}); err != nil {
		return xerrors.Errorf("unable to write workload results: %w", err)
	}

	if err := report.Write(rbacReport, report.Option{
		Format:        opt.Format,
		Report:        opt.KubernetesOption.ReportFormat,
		Output:        opt.Output,
		Severities:    opt.Severities,
		ColumnHeading: report.ColumnHeading(opt.ReportOption, report.RoleColumns()),
	}); err != nil {
		return xerrors.Errorf("unable to write rbac results: %w", err)
	}

	cmd.Exit(opt, r.Failed())

	return nil
}

func separateMisConfigRoleAssessment(k8sReport report.Report, rp option.ReportOption) (report.Report, report.Report) {
	workloadMisconfig := make([]report.Resource, 0)
	rbacAssessment := make([]report.Resource, 0)
	for _, misConfig := range k8sReport.Misconfigurations {
		if slices.Contains(rp.SecurityChecks, types.SecurityCheckRbac) && rbacResource(misConfig) {
			rbacAssessment = append(rbacAssessment, misConfig)
		} else {
			if slices.Contains(rp.SecurityChecks, types.SecurityCheckConfig) && !rbacResource(misConfig) {
				workloadMisconfig = append(workloadMisconfig, misConfig)
			}
		}
	}
	return report.Report{
			SchemaVersion:     0,
			ClusterName:       k8sReport.ClusterName,
			Vulnerabilities:   k8sReport.Vulnerabilities,
			Misconfigurations: workloadMisconfig,
		}, report.Report{
			SchemaVersion:     0,
			ClusterName:       k8sReport.ClusterName,
			Misconfigurations: rbacAssessment,
		}
}

func rbacResource(misConfig report.Resource) bool {
	return misConfig.Kind == "Role" || misConfig.Kind == "RoleBinding" || misConfig.Kind == "ClusterRole" || misConfig.Kind == "ClusterRoleBinding"
}

// Full-cluster scanning with '--format table' without explicit '--report all' is not allowed so that it won't mess up user's terminal.
// To show all the results, user needs to specify "--report all" explicitly
// even though the default value of "--report" is "all".
//
// e.g. $ trivy k8s --report all cluster
//      $ trivy k8s --report all all
//
// Or they can use "--format json" with implicit "--report all".
//
// e.g. $ trivy k8s --format json cluster // All the results are shown in JSON
//
// Single resource scanning is allowed with implicit "--report all".
//
// e.g. $ trivy k8s pod myapp
func validateReportArguments(cliCtx *cli.Context) error {
	if cliCtx.String("report") == "all" &&
		!cliCtx.IsSet("report") &&
		cliCtx.String("format") == "table" {

		m := "All the results in the table format can mess up your terminal. Use \"--report all\" to tell Trivy to output it to your terminal anyway, or consider \"--report summary\" to show the summary output."

		return xerrors.New(m)
	}

	return nil
}
