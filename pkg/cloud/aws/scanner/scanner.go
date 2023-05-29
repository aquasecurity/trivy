package scanner

import (
	"context"
	"fmt"
	"golang.org/x/xerrors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/scanners/cloud/aws"
	"github.com/aquasecurity/defsec/pkg/scanners/options"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/trivy/pkg/cloud/aws/cache"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

type AWSScanner struct {
}

func NewScanner() *AWSScanner {
	return &AWSScanner{}
}

func (s *AWSScanner) Scan(ctx context.Context, option flag.Options) (scan.Results, bool, error) {

	awsCache := cache.New(option.CacheDir, option.MaxCacheAge, option.Account, option.Region)
	included, missing := awsCache.ListServices(option.Services)

	var scannerOpts []options.ScannerOption
	if !option.NoProgress {
		tracker := newProgressTracker()
		defer tracker.Finish()
		scannerOpts = append(scannerOpts, aws.ScannerWithProgressTracker(tracker))
	}

	if len(missing) > 0 {
		scannerOpts = append(scannerOpts, aws.ScannerWithAWSServices(missing...))
	}

	if option.Debug {
		scannerOpts = append(scannerOpts, options.ScannerWithDebug(&defsecLogger{}))
	}

	if option.Trace {
		scannerOpts = append(scannerOpts, options.ScannerWithTrace(&defsecLogger{}))
	}

	if option.Region != "" {
		scannerOpts = append(
			scannerOpts,
			aws.ScannerWithAWSRegion(option.Region),
		)
	}

	if option.Endpoint != "" {
		scannerOpts = append(
			scannerOpts,
			aws.ScannerWithAWSEndpoint(option.Endpoint),
		)
	}

	var policyPaths []string
	var downloadedPolicyPaths []string
	var err error
	downloadedPolicyPaths, err = operation.InitBuiltinPolicies(context.Background(), option.CacheDir, option.Quiet, option.SkipPolicyUpdate)
	if err != nil {
		if !option.SkipPolicyUpdate {
			log.Logger.Errorf("Falling back to embedded policies: %s", err)
		}
	} else {
		log.Logger.Debug("Policies successfully loaded from disk")
		policyPaths = append(policyPaths, downloadedPolicyPaths...)
		scannerOpts = append(scannerOpts,
			options.ScannerWithEmbeddedPolicies(false))
	}

	policyPaths = append(policyPaths, option.RegoOptions.PolicyPaths...)
	policyFS, policyPaths, err := createPolicyFS(option.RegoOptions.PolicyPaths)
	if err != nil {
		log.Logger.Errorf("Could not load config data: %s", err)
	}
	if policyFS != nil {
		scannerOpts = append(scannerOpts, options.ScannerWithPolicyFilesystem(policyFS))
	}
	if len(policyPaths) > 0 {
		scannerOpts = append(scannerOpts, options.ScannerWithPolicyDirs(policyPaths...))
	}
	//scannerOpts = append(scannerOpts, options.ScannerWithPolicyDirs(policyPaths...))
	//scannerOpts = append(scannerOpts, options.ScannerWithPolicyFilesystem(nil))

	dataFS, dataPaths, err := createDataFS(option.RegoOptions.DataPaths)
	if err != nil {
		log.Logger.Errorf("Could not load config data: %s", err)
	}
	scannerOpts = append(scannerOpts, options.ScannerWithDataDirs(dataPaths...))
	scannerOpts = append(scannerOpts, options.ScannerWithDataFilesystem(dataFS))

	if len(option.RegoOptions.PolicyNamespaces) > 0 {
		scannerOpts = append(
			scannerOpts,
			options.ScannerWithPolicyNamespaces(option.RegoOptions.PolicyNamespaces...),
		)
	}

	if option.Compliance.Spec.ID != "" {
		scannerOpts = append(scannerOpts, options.ScannerWithSpec(option.Compliance.Spec.ID))
	} else {
		scannerOpts = append(scannerOpts, options.ScannerWithFrameworks(
			framework.Default,
			framework.CIS_AWS_1_2))
	}

	scanner := aws.New(scannerOpts...)

	var freshState *state.State
	if len(missing) > 0 || option.CloudOptions.UpdateCache {
		var err error
		freshState, err = scanner.CreateState(ctx)
		if err != nil {
			return nil, false, err
		}
	}

	var fullState *state.State
	if previousState, err := awsCache.LoadState(); err == nil {
		if freshState != nil {
			fullState, err = previousState.Merge(freshState)
			if err != nil {
				return nil, false, err
			}
		} else {
			fullState = previousState
		}
	} else {
		fullState = freshState
	}

	if fullState == nil {
		return nil, false, fmt.Errorf("no resultant state found")
	}

	if err := awsCache.AddServices(fullState, missing); err != nil {
		return nil, false, err
	}

	defsecResults, err := scanner.Scan(ctx, fullState)
	if err != nil {
		return nil, false, err
	}

	return defsecResults, len(included) > 0, nil
}

func createPolicyFS(policyPaths []string) (fs.FS, []string, error) {
	if len(policyPaths) == 0 {
		return nil, nil, nil
	}

	mfs := mapfs.New()
	for _, p := range policyPaths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to derive absolute path from '%s': %w", p, err)
		}
		if err = mfs.CopyFilesUnder(abs); err != nil {
			return nil, nil, xerrors.Errorf("mapfs file copy error: %w", err)
		}
	}

	// policy paths are no longer needed as fs.FS contains only needed files now.
	policyPaths = []string{"."}

	return mfs, policyPaths, nil
}

func createDataFS(dataPaths []string) (fs.FS, []string, error) {
	fsys := mapfs.New()
	//k8sVersion := "a"
	// Create a virtual file for Kubernetes scanning
	//if k8sVersion != "" {
	//	if err := fsys.MkdirAll("system", 0700); err != nil {
	//		return nil, nil, err
	//	}
	//	data := []byte(fmt.Sprintf(`{"k8s": {"version": "%s"}}`, k8sVersion))
	//	if err := fsys.WriteVirtualFile("system/k8s-version.json", data, 0600); err != nil {
	//		return nil, nil, err
	//	}
	//}
	for _, path := range dataPaths {
		if err := fsys.CopyFilesUnder(path); err != nil {
			return nil, nil, err
		}
	}

	// data paths are no longer needed as fs.FS contains only needed files now.
	dataPaths = []string{"."}

	return fsys, dataPaths, nil
}

type defsecLogger struct {
}

func (d *defsecLogger) Write(p []byte) (n int, err error) {
	log.Logger.Debug("[defsec] " + strings.TrimSpace(string(p)))
	return len(p), nil
}
