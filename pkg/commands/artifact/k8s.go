package artifact

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/cheggaaa/pb/v3"
	"github.com/urfave/cli/v2"
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v2"

	"github.com/aquasecurity/trivy/pkg/log"
	pkgReport "github.com/aquasecurity/trivy/pkg/report"
	k8sReport "github.com/aquasecurity/trivy/pkg/report/k8s"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	"github.com/aquasecurity/trivy-kubernetes/pkg/k8s"
	"github.com/aquasecurity/trivy-kubernetes/pkg/trivyk8s"
)

// K8sRun runs scan on kubernetes cluster
func K8sRun(cliCtx *cli.Context) error {
	opt, err := InitOption(cliCtx)
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

	runner, err := NewRunner(opt)
	if err != nil {
		if errors.Is(err, SkipScan) {
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
	k8sArtifacts, err := trivyk8s.ListArtifacts(ctx)
	if err != nil {
		return xerrors.Errorf("get k8s artifacts error: %w", err)
	}

	report, err := k8sRun(ctx, runner, opt, k8sArtifacts)
	if err != nil {
		return xerrors.Errorf("k8s scan error: %w", err)
	}
	report.ClusterName = cluster.GetCurrentContext()

	if err = k8sReport.Write(report, pkgReport.Option{
		Format: opt.KubernetesOption.ReportFormat, // for now json is the default
		Output: opt.Output,
	}, opt.Severities); err != nil {
		return xerrors.Errorf("unable to write results: %w", err)
	}

	exit(opt, report.Failed())

	return nil
}

func k8sRun(ctx context.Context, runner *Runner, opt Option, artifacts []*artifacts.Artifact) (k8sReport.Report, error) {
	opt.SecurityChecks = []string{types.SecurityCheckVulnerability, types.SecurityCheckConfig}

	// progress bar
	bar := pb.StartNew(len(artifacts))
	if opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	vulns := make([]k8sReport.Resource, 0)
	misconfigs := make([]k8sReport.Resource, 0)

	// disable logs before scanning
	err := log.InitLogger(opt.Debug, true)
	if err != nil {
		return k8sReport.Report{}, xerrors.Errorf("logger error: %w", err)
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
				vulns = append(vulns, newK8sResource(artifact, imageReport, err))
				continue
			}

			imageReport, err = runner.Filter(ctx, opt, imageReport)
			if err != nil {
				return k8sReport.Report{}, xerrors.Errorf("filter error: %w", err)
			}

			vulns = append(vulns, newK8sResource(artifact, imageReport, nil))
		}

		// scan configurations
		configFile, err := createTempFile(artifact)
		if err != nil {
			return k8sReport.Report{}, xerrors.Errorf("scan error: %w", err)
		}

		opt.Target = configFile
		configReport, err := runner.ScanFilesystem(ctx, opt)
		removeFile(configFile)
		if err != nil {
			// add error to report
			log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
			misconfigs = append(misconfigs, newK8sResource(artifact, configReport, err))
		}

		configReport, err = runner.Filter(ctx, opt, configReport)
		if err != nil {
			return k8sReport.Report{}, xerrors.Errorf("filter error: %w", err)
		}

		misconfigs = append(misconfigs, newK8sResource(artifact, configReport, nil))
	}

	// enable logs after scanning
	err = log.InitLogger(opt.Debug, opt.Quiet)
	if err != nil {
		return k8sReport.Report{}, xerrors.Errorf("logger error: %w", err)
	}

	return k8sReport.Report{
		SchemaVersion:     0,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}

func createTempFile(artifact *artifacts.Artifact) (string, error) {
	filename := fmt.Sprintf("%s-%s-%s-*.yaml", artifact.Namespace, artifact.Kind, artifact.Name)

	file, err := os.CreateTemp("", filename)
	if err != nil {
		return "", xerrors.Errorf("creating tmp file error: %w", err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Logger.Errorf("failed to close temp file %s: %s:", file.Name(), err)
		}
	}()

	// TODO(josedonizetti): marshal and return as byte slice should be on the trivy-kubernetes library?
	data, err := yaml.Marshal(artifact.RawResource)
	if err != nil {
		removeFile(filename)
		return "", xerrors.Errorf("marshaling resource error: %w", err)
	}

	_, err = file.Write(data)
	if err != nil {
		removeFile(filename)
		return "", xerrors.Errorf("writing tmp file error: %w", err)
	}

	return file.Name(), nil
}

func newK8sResource(artifact *artifacts.Artifact, report types.Report, err error) k8sReport.Resource {
	results := make([]types.Result, 0, len(report.Results))
	// fix target name
	for _, result := range report.Results {
		// if resource is a kubernetes file fix the target name,
		// to avoid showing the temp file that was removed.
		if result.Type == "kubernetes" {
			result.Target = fmt.Sprintf("%s/%s", artifact.Kind, artifact.Name)
		}
		results = append(results, result)
	}

	k8sreport := k8sReport.Resource{
		Namespace: artifact.Namespace,
		Kind:      artifact.Kind,
		Name:      artifact.Name,
		Results:   results,
	}

	// if there was any error during the scan
	if err != nil {
		k8sreport.Error = err.Error()
	}

	return k8sreport
}

func removeFile(filename string) {
	if err := os.Remove(filename); err != nil {
		log.Logger.Errorf("failed to remove temp file %s: %s:", filename, err)
	}
}
