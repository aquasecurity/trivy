package scanner

import (
	"context"
	_ "embed"
	"path/filepath"

	cfExternal "github.com/aquasecurity/cfsec/pkg/externalscan"
	"github.com/aquasecurity/defsec/rules"
	tfExternal "github.com/aquasecurity/tfsec/pkg/externalscan"
	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/policy"
	"github.com/aquasecurity/fanal/types"
)

//go:embed detection.rego
var defaultDetectionModule string

type Scanner struct {
	rootDir    string
	namespaces []string
	engine     *policy.Engine

	// for Terraform
	tfscanner *tfExternal.ExternalScanner

	// for CloudFormation
	cfScanner *cfExternal.ExternalScanner
}

func New(rootDir string, namespaces, policyPaths, dataPaths []string, trace bool) (Scanner, error) {
	scanner := Scanner{
		rootDir:    rootDir,
		namespaces: namespaces,
		tfscanner:  tfExternal.NewExternalScanner(tfExternal.OptionIncludePassed()),
		cfScanner:  cfExternal.NewExternalScanner(cfExternal.OptionIncludePassed()),
	}

	if len(namespaces) > 0 && len(policyPaths) > 0 {
		engine, err := policy.Load(policyPaths, dataPaths, trace)
		if err != nil {
			return Scanner{}, xerrors.Errorf("policy load error: %w", err)
		}
		scanner.engine = engine
	}

	return scanner, nil
}

func (s Scanner) ScanConfigs(ctx context.Context, files []types.Config) ([]types.Misconfiguration, error) {
	var configFiles, tfFiles, cfFiles []types.Config
	for _, file := range files {
		switch file.Type {
		case types.Terraform:
			tfFiles = append(tfFiles, file)
		case types.CloudFormation:
			cfFiles = append(cfFiles, file)
		default:
			configFiles = append(configFiles, file)
		}
	}

	var misconfs []types.Misconfiguration

	// Scan config files by OPA/Rego
	results, err := s.scanConfigsByRego(ctx, configFiles)
	if err != nil {
		return nil, xerrors.Errorf("scan config error: %w", err)
	}
	misconfs = append(misconfs, results...)

	// Scan terraform files by TFSec
	results, err = s.scanTerraformByTFSec(tfFiles)
	if err != nil {
		return nil, xerrors.Errorf("scan terraform error: %w", err)
	}
	misconfs = append(misconfs, results...)

	// Scan CloudFormation files by CFSec
	results, err = s.scanCloudFormationByCFSec(cfFiles)
	if err != nil {
		return nil, xerrors.Errorf("scan cloudformation error: %w", err)
	}
	misconfs = append(misconfs, results...)

	return misconfs, nil
}

func (s Scanner) scanConfigsByRego(ctx context.Context, files []types.Config) ([]types.Misconfiguration, error) {
	if s.engine == nil {
		return nil, nil
	}

	var configs []types.Config
	for _, file := range files {
		// Detect config types such as CloudFormation and Kubernetes.
		configType, err := detectType(ctx, file.Content)
		if err != nil {
			return nil, xerrors.Errorf("unable to detect config type: %w", err)
		}
		if configType != "" {
			file.Type = configType
		}

		configs = append(configs, file)
	}

	misconfs, err := s.engine.Check(ctx, configs, s.namespaces)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan: %w", err)
	}

	return misconfs, nil
}

func (s Scanner) scanCloudFormationByCFSec(files []types.Config) ([]types.Misconfiguration, error) {
	if len(files) == 0 {
		return nil, nil
	}

	misConfs := map[string]types.Misconfiguration{}
	for _, file := range files {
		results, err := s.cfScanner.Scan(file.FilePath)
		if err != nil {
			return nil, xerrors.Errorf("cloudformation scan error: %w", err)
		}
		rootDir, err := filepath.Abs(s.rootDir)
		if err != nil {
			return nil, xerrors.Errorf("filepath abs (%s): %w", s.rootDir, err)
		}

		for _, result := range results {
			misconfResult := types.MisconfResult{
				Message: result.Description,
				PolicyMetadata: types.PolicyMetadata{
					ID:                 result.AVDID,
					Type:               "Cloudformation Security Check powered by cfsec",
					Title:              result.RuleSummary,
					Description:        result.Impact,
					Severity:           string(result.Severity),
					RecommendedActions: result.Resolution,
					References:         result.Links,
				},
				IacMetadata: types.IacMetadata{
					Resource:  result.Resource,
					StartLine: result.Location.StartLine,
					EndLine:   result.Location.EndLine,
				},
			}

			filePath, err := filepath.Rel(rootDir, result.Location.Filename)
			if err != nil {
				return nil, xerrors.Errorf("filepath rel: %w", err)
			}

			misconf, ok := misConfs[filePath]
			if !ok {
				misconf = types.Misconfiguration{
					FileType: types.CloudFormation,
					FilePath: filePath,
				}
			}

			if result.Status == rules.StatusPassed {
				misconf.Successes = append(misconf.Successes, misconfResult)
			} else {
				misconf.Failures = append(misconf.Failures, misconfResult)
			}
			misConfs[filePath] = misconf
		}
	}

	return types.ToMisconfigurations(misConfs), nil
}

// scanTerraformByTFSec scans terraform files by using tfsec/tfsec
func (s Scanner) scanTerraformByTFSec(files []types.Config) ([]types.Misconfiguration, error) {
	if len(files) == 0 {
		return nil, nil
	}

	for _, file := range files {
		if err := s.tfscanner.AddPath(file.FilePath); err != nil {
			return nil, xerrors.Errorf("terraform path error: %w", err)
		}
	}
	results, err := s.tfscanner.Scan()
	if err != nil {
		return nil, xerrors.Errorf("terraform scan error: %w", err)
	}

	rootDir, err := filepath.Abs(s.rootDir)
	if err != nil {
		return nil, xerrors.Errorf("filepath abs (%s): %w", s.rootDir, err)
	}

	misconfs := map[string]types.Misconfiguration{}
	for _, result := range results {
		misconfResult := types.MisconfResult{
			Message: result.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 result.RuleID,
				Type:               "Terraform Security Check powered by tfsec",
				Title:              result.RuleSummary,
				Description:        result.Impact,
				Severity:           string(result.Severity),
				RecommendedActions: result.Resolution,
				References:         result.Links,
			},
			IacMetadata: types.IacMetadata{
				Resource:  result.Resource,
				StartLine: result.Location.StartLine,
				EndLine:   result.Location.EndLine,
			},
		}

		filePath, err := filepath.Rel(rootDir, result.Range().Filename)
		if err != nil {
			return nil, xerrors.Errorf("filepath rel: %w", err)
		}

		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = types.Misconfiguration{
				FileType: types.Terraform,
				FilePath: filePath,
			}
		}

		if result.Passed() {
			misconf.Successes = append(misconf.Successes, misconfResult)
		} else {
			misconf.Failures = append(misconf.Failures, misconfResult)
		}
		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs), nil
}

func detectType(ctx context.Context, input interface{}) (string, error) {
	results, err := rego.New(
		rego.Input(input),
		rego.Query("x = data.config.type.detect"),
		rego.Module("detection.rego", defaultDetectionModule),
	).Eval(ctx)
	if err != nil {
		return "", xerrors.Errorf("rego eval error: %w", err)
	}

	for _, result := range results {
		for _, configType := range result.Bindings["x"].([]interface{}) {
			v, ok := configType.(string)
			if !ok {
				return "", xerrors.Errorf("'detect' must return string")
			}
			// Return the first element
			return v, nil
		}
	}
	return "", nil
}
