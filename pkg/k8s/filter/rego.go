package filter

import (
	"context"
	"os"
	"path/filepath"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
)

// K8sArtifact represents Kubernetes resource metadata for REGO filtering
type K8sArtifact struct {
	Kind        string            `json:"kind"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	Spec        any               `json:"spec,omitempty"`
}

// RegoFilter handles REGO-based filtering for Kubernetes artifacts
type RegoFilter struct {
	query rego.PreparedEvalQuery
}

// NewRegoFilter creates a new REGO filter instance
func NewRegoFilter(ctx context.Context, opts flag.K8sOptions) (*RegoFilter, error) {
	if opts.K8sFilterPolicy == "" {
		return nil, nil // No policy specified, no filtering needed
	}

	policy, err := os.ReadFile(opts.K8sFilterPolicy)
	if err != nil {
		return nil, xerrors.Errorf("unable to read the K8s filter policy file: %w", err)
	}

	// Create rego query
	regoOptions := []func(*rego.Rego){
		rego.Query("data.trivy.kubernetes.ignore"),
		rego.Module("trivy-k8s.rego", string(policy)),
		rego.SetRegoVersion(ast.RegoV0),
	}

	// Add data files if specified
	for _, dataFile := range opts.K8sFilterData {
		data, err := os.ReadFile(dataFile)
		if err != nil {
			return nil, xerrors.Errorf("unable to read K8s filter data file %s: %w", dataFile, err)
		}

		// Use the file name as the module name
		moduleName := filepath.Base(dataFile)
		regoOptions = append(regoOptions, rego.Module(moduleName, string(data)))
	}

	query, err := rego.New(regoOptions...).PrepareForEval(ctx)
	if err != nil {
		return nil, xerrors.Errorf("unable to prepare K8s filter policy for eval: %w", err)
	}

	return &RegoFilter{query: query}, nil
}

// ShouldIgnore evaluates if the given Kubernetes artifact should be ignored based on REGO policy
func (f *RegoFilter) ShouldIgnore(ctx context.Context, artifact K8sArtifact) (bool, error) {
	if f == nil {
		return false, nil // No filter configured
	}

	results, err := f.query.Eval(ctx, rego.EvalInput(artifact))
	if err != nil {
		return false, xerrors.Errorf("unable to evaluate K8s filter policy: %w", err)
	}

	if len(results) == 0 {
		// Handle undefined result - default to not ignoring
		return false, nil
	}

	ignore, ok := results[0].Expressions[0].Value.(bool)
	if !ok {
		// Handle unexpected result type
		return false, xerrors.New("K8s filter policy must return boolean")
	}

	return ignore, nil
}

// ConvertToK8sArtifact converts common Kubernetes resource fields to K8sArtifact
func ConvertToK8sArtifact(kind, namespace, name string, labels, annotations map[string]string, spec any) K8sArtifact {
	// Ensure maps are not nil to avoid JSON marshaling issues
	if labels == nil {
		labels = make(map[string]string)
	}
	if annotations == nil {
		annotations = make(map[string]string)
	}

	return K8sArtifact{
		Kind:        kind,
		Namespace:   namespace,
		Name:        name,
		Labels:      labels,
		Annotations: annotations,
		Spec:        spec,
	}
}
