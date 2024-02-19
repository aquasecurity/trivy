package parser

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"

	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func loadBlocksFromFile(file sourceFile, moduleSource string) (hcl.Blocks, []terraform.Ignore, error) {
	ignores := parseIgnores(file.file.Bytes, file.path, moduleSource)
	contents, diagnostics := file.file.Body.Content(terraform.Schema)
	if diagnostics != nil && diagnostics.HasErrors() {
		return nil, nil, diagnostics
	}
	if contents == nil {
		return nil, nil, nil
	}
	return contents.Blocks, ignores, nil
}

func parseIgnores(data []byte, path, moduleSource string) []terraform.Ignore {
	var ignores []terraform.Ignore
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		lineIgnores := parseIgnoresFromLine(line)
		for _, lineIgnore := range lineIgnores {
			lineIgnore.Range = types.NewRange(path, i+1, i+1, moduleSource, nil)
			ignores = append(ignores, lineIgnore)
		}
	}
	for a, ignoreA := range ignores {
		if !ignoreA.Block {
			continue
		}
		for _, ignoreB := range ignores {
			if !ignoreB.Block {
				continue
			}
			if ignoreA.Range.GetStartLine()+1 == ignoreB.Range.GetStartLine() {
				ignoreA.Range = ignoreB.Range
				ignores[a] = ignoreA
			}
		}
	}
	return ignores

}

var commentPattern = regexp.MustCompile(`^\s*([/]+|/\*|#)+\s*tfsec:`)
var trivyCommentPattern = regexp.MustCompile(`^\s*([/]+|/\*|#)+\s*trivy:`)

func parseIgnoresFromLine(input string) []terraform.Ignore {

	var ignores []terraform.Ignore

	input = commentPattern.ReplaceAllString(input, "tfsec:")
	input = trivyCommentPattern.ReplaceAllString(input, "trivy:")

	bits := strings.Split(strings.TrimSpace(input), " ")
	for i, bit := range bits {
		bit := strings.TrimSpace(bit)
		bit = strings.TrimPrefix(bit, "#")
		bit = strings.TrimPrefix(bit, "//")
		bit = strings.TrimPrefix(bit, "/*")

		if strings.HasPrefix(bit, "tfsec:") || strings.HasPrefix(bit, "trivy:") {
			ignore, err := parseIgnoreFromComment(bit)
			if err != nil {
				continue
			}
			ignore.Block = i == 0
			ignores = append(ignores, *ignore)
		}
	}

	return ignores
}

func parseIgnoreFromComment(input string) (*terraform.Ignore, error) {
	var ignore terraform.Ignore
	if !strings.HasPrefix(input, "tfsec:") && !strings.HasPrefix(input, "trivy:") {
		return nil, fmt.Errorf("invalid ignore")
	}

	input = input[6:]

	segments := strings.Split(input, ":")

	for i := 0; i < len(segments)-1; i += 2 {
		key := segments[i]
		val := segments[i+1]
		switch key {
		case "ignore":
			ignore.RuleID, ignore.Params = parseIDWithParams(val)
		case "exp":
			parsed, err := time.Parse("2006-01-02", val)
			if err != nil {
				return &ignore, err
			}
			ignore.Expiry = &parsed
		case "ws":
			ignore.Workspace = val
		}
	}

	return &ignore, nil
}

func parseIDWithParams(input string) (string, map[string]string) {
	params := make(map[string]string)
	if !strings.Contains(input, "[") {
		return input, params
	}
	parts := strings.Split(input, "[")
	id := parts[0]
	paramStr := strings.TrimSuffix(parts[1], "]")
	for _, pair := range strings.Split(paramStr, ",") {
		parts := strings.Split(pair, "=")
		if len(parts) != 2 {
			continue
		}
		params[parts[0]] = parts[1]
	}
	return id, params
}
