package rego

import (
	"fmt"
	"io/fs"
	"strconv"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/open-policy-agent/opa/rego"
)

type regoResult struct {
	Filepath  string
	Resource  string
	StartLine int
	EndLine   int
	Message   string
	Explicit  bool
	Managed   bool
	FSKey     string
	FS        fs.FS
}

func (r regoResult) GetMetadata() types.Metadata {
	if !r.Managed {
		return types.NewUnmanagedMetadata()
	}
	rng := types.NewRangeWithFSKey(r.Filepath, r.StartLine, r.EndLine, "", r.FSKey, r.FS)
	ref := types.NewNamedReference(r.Resource)
	if r.Explicit {
		return types.NewExplicitMetadata(rng, ref)
	}
	return types.NewMetadata(rng, ref)
}

func (r regoResult) GetRawValue() interface{} {
	return nil
}

func parseResult(raw interface{}) *regoResult {
	var result regoResult
	result.Managed = true
	switch val := raw.(type) {
	case []interface{}:
		var msg string
		for _, item := range val {
			switch raw := item.(type) {
			case map[string]interface{}:
				result = parseCause(raw)
			case string:
				msg = raw
			}
		}
		result.Message = msg
	case string:
		result.Message = val
	case map[string]interface{}:
		result = parseCause(val)
	default:
		result.Message = "Rego policy resulted in DENY"
	}
	return &result
}

func parseCause(cause map[string]interface{}) regoResult {
	var result regoResult
	result.Managed = true
	if msg, ok := cause["msg"]; ok {
		result.Message = fmt.Sprintf("%s", msg)
	}
	if filepath, ok := cause["filepath"]; ok {
		result.Filepath = fmt.Sprintf("%s", filepath)
	}
	if msg, ok := cause["fskey"]; ok {
		result.FSKey = fmt.Sprintf("%s", msg)
	}
	if msg, ok := cause["resource"]; ok {
		result.Resource = fmt.Sprintf("%s", msg)
	}
	if start, ok := cause["startline"]; ok {
		result.StartLine = parseLineNumber(start)
	}
	if end, ok := cause["endline"]; ok {
		result.EndLine = parseLineNumber(end)
	}
	if explicit, ok := cause["explicit"]; ok {
		if set, ok := explicit.(bool); ok {
			result.Explicit = set
		}
	}
	if managed, ok := cause["managed"]; ok {
		if set, ok := managed.(bool); ok {
			result.Managed = set
		}
	}
	return result
}

func parseLineNumber(raw interface{}) int {
	str := fmt.Sprintf("%s", raw)
	n, _ := strconv.Atoi(str)
	return n
}

func (s *Scanner) convertResults(set rego.ResultSet, input Input, namespace string, rule string, traces []string) scan.Results {
	var results scan.Results
	for _, result := range set {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]interface{})
			if !ok {
				regoResult := parseResult(expression.Value)
				regoResult.FS = input.FS
				if regoResult.Filepath == "" && input.Path != "" {
					regoResult.Filepath = input.Path
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego policy rule: %s.%s", namespace, rule)
				}
				results.AddRego(regoResult.Message, namespace, rule, traces, regoResult)
				continue
			}

			for _, value := range values {
				regoResult := parseResult(value)
				regoResult.FS = input.FS
				if regoResult.Filepath == "" && input.Path != "" {
					regoResult.Filepath = input.Path
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego policy rule: %s.%s", namespace, rule)
				}
				results.AddRego(regoResult.Message, namespace, rule, traces, regoResult)
			}
		}
	}
	return results
}

func (s *Scanner) embellishResultsWithRuleMetadata(results scan.Results, metadata StaticMetadata) scan.Results {
	results.SetRule(metadata.ToRule())
	return results
}
