package scanner

import (
	"context"
	_ "embed"

	"github.com/open-policy-agent/opa/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/policy"
	"github.com/aquasecurity/fanal/types"
)

var (
	//go:embed detection.rego
	defaultDetectionModule string
)

type Scanner struct {
	namespaces []string
	engine     *policy.Engine
}

func New(namespaces, policyPaths, dataPaths []string) (Scanner, error) {
	if len(namespaces) == 0 || len(policyPaths) == 0 {
		return Scanner{}, nil
	}

	engine, err := policy.Load(policyPaths, dataPaths)
	if err != nil {
		return Scanner{}, xerrors.Errorf("policy load error: %w", err)
	}

	return Scanner{
		namespaces: namespaces,
		engine:     engine,
	}, nil
}

func (s Scanner) ScanConfigs(ctx context.Context, files []types.Config) ([]types.Misconfiguration, error) {
	if len(s.namespaces) == 0 {
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
