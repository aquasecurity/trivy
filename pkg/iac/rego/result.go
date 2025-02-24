package rego

import (
	"fmt"
	"io/fs"
	"strconv"

	"github.com/open-policy-agent/opa/rego"

	"github.com/aquasecurity/trivy/pkg/iac/scan"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type regoResult struct {
	Filepath     string
	Resource     string
	StartLine    int
	EndLine      int
	SourcePrefix string
	Message      string
	Explicit     bool
	Managed      bool
	FSKey        string
	FS           fs.FS
	Parent       *regoResult
}

func (r regoResult) GetMetadata() iacTypes.Metadata {
	var m iacTypes.Metadata
	if !r.Managed {
		m = iacTypes.NewUnmanagedMetadata()
	} else {
		rng := iacTypes.NewRangeWithFSKey(r.Filepath, r.StartLine, r.EndLine, r.SourcePrefix, r.FSKey, r.FS)
		if r.Explicit {
			m = iacTypes.NewExplicitMetadata(rng, r.Resource)
		} else {
			m = iacTypes.NewMetadata(rng, r.Resource)
		}
	}
	if r.Parent != nil {
		return m.WithParent(r.Parent.GetMetadata())
	}
	return m
}

func (r regoResult) GetRawValue() any {
	return nil
}

func parseResult(raw any) *regoResult {
	var result regoResult
	result.Managed = true
	switch val := raw.(type) {
	case []any:
		var msg string
		for _, item := range val {
			switch raw := item.(type) {
			case map[string]any:
				result = parseCause(raw)
			case string:
				msg = raw
			}
		}
		result.Message = msg
	case string:
		result.Message = val
	case map[string]any:
		result = parseCause(val)
	default:
		result.Message = "Rego check resulted in DENY"
	}
	return &result
}

func parseCause(cause map[string]any) regoResult {
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
	if prefix, ok := cause["sourceprefix"]; ok {
		result.SourcePrefix = fmt.Sprintf("%s", prefix)
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
	if parent, ok := cause["parent"]; ok {
		if m, ok := parent.(map[string]any); ok {
			parentResult := parseCause(m)
			result.Parent = &parentResult
		}
	}
	return result
}

func parseLineNumber(raw any) int {
	str := fmt.Sprintf("%s", raw)
	n, _ := strconv.Atoi(str)
	return n
}

func (s *Scanner) convertResults(resultSet rego.ResultSet, input Input, namespace, rule string, traces []string) scan.Results {
	var results scan.Results

	offset := 0
	if input.Contents != nil {
		if xx, ok := input.Contents.(map[string]any); ok {
			if md, ok := xx["__defsec_metadata"]; ok {
				if md2, ok := md.(map[string]any); ok {
					if sl, ok := md2["offset"]; ok {
						offset, _ = sl.(int)
					}
				}
			}
		}
	}
	for _, result := range resultSet {
		for _, expression := range result.Expressions {
			values, ok := expression.Value.([]any)
			if !ok {
				values = []any{expression.Value}
			}

			for _, value := range values {
				regoResult := parseResult(value)
				regoResult.FS = input.FS
				if regoResult.Filepath == "" && input.Path != "" {
					regoResult.Filepath = input.Path
				}
				if regoResult.Message == "" {
					regoResult.Message = fmt.Sprintf("Rego check rule: %s.%s", namespace, rule)
				}
				regoResult.StartLine += offset
				regoResult.EndLine += offset
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
