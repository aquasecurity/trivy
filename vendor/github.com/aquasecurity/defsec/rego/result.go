package rego

import (
	"fmt"
	"strconv"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/rules"
	"github.com/open-policy-agent/opa/rego"
)

type regoResult struct {
	Filepath  string
	StartLine int
	EndLine   int
	Message   string
	Explicit  bool
	Managed   bool
}

func (r regoResult) GetMetadata() types.Metadata {
	if !r.Managed {
		return types.NewUnmanagedMetadata()
	}
	rng := types.NewRange(r.Filepath, r.StartLine, r.EndLine)
	ref := types.NewNamedReference(rng.String())
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

func (s *Scanner) convertResults(set rego.ResultSet, filepath string, namespace string, rule string) rules.Results {
	var results rules.Results
	for _, result := range set {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]interface{})
			if !ok {
				regoResult := parseResult(expression.Value)
				if regoResult.Filepath == "" && filepath != "" {
					regoResult.Filepath = filepath
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego policy rule: %s.%s", namespace, rule)
				}
				results.AddRego(regoResult.Message, namespace, rule, regoResult)
				continue
			}

			for _, value := range values {
				regoResult := parseResult(value)
				if regoResult.Filepath == "" && filepath != "" {
					regoResult.Filepath = filepath
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego policy rule: %s.%s", namespace, rule)
				}
				results.AddRego(regoResult.Message, namespace, rule, regoResult)
			}
		}
	}
	return results
}

func (s *Scanner) embellishResultsWithRuleMetadata(results rules.Results, metadata StaticMetadata) rules.Results {
	results.SetRule(metadata.ToRule())
	return results
}
