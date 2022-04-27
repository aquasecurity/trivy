package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
)

func (r *Rule) CheckAgainstState(s *state.State) rules.Results {
	results := r.Base.Evaluate(s)
	if len(results) > 0 {
		results.SetRule(r.Base.Rule())
	}
	return results
}

func (r *Rule) CheckAgainstBlock(b *terraform.Block, m *terraform.Module) rules.Results {
	if r.CheckTerraform == nil {
		return nil
	}
	if !r.isRuleRequiredForBlock(b) {
		return nil
	}
	results := r.CheckTerraform(b, m)
	if len(results) > 0 {
		base := r.Base.Rule()
		results.SetRule(base)
	}
	return results
}

// IsRuleRequiredForBlock returns true if the Rule should be applied to the given HCL block
func (r *Rule) isRuleRequiredForBlock(b *terraform.Block) bool {

	if len(r.RequiredTypes) > 0 {
		if !r.checkRequiredTypesMatch(b) {
			return false
		}
	}

	if len(r.RequiredLabels) > 0 {
		if !r.checkRequiredLabelsMatch(b) {
			return false
		}

	}

	if len(r.RequiredSources) > 0 && b.Type() == terraform.TypeModule.Name() {
		if !r.checkRequiredSourcesMatch(b) {
			return false
		}
	}

	return true
}

func (r *Rule) checkRequiredTypesMatch(b *terraform.Block) bool {
	var found bool
	for _, requiredType := range r.RequiredTypes {
		if b.Type() == requiredType {
			found = true
			break
		}
	}

	return found
}

func (r *Rule) checkRequiredLabelsMatch(b *terraform.Block) bool {
	var found bool
	for _, requiredLabel := range r.RequiredLabels {
		if requiredLabel == "*" || (len(b.Labels()) > 0 && wildcardMatch(requiredLabel, b.TypeLabel())) {
			found = true
			break
		}
	}

	return found
}

func (r *Rule) checkRequiredSourcesMatch(b *terraform.Block) bool {
	var found bool
	if sourceAttr := b.GetAttribute("source"); sourceAttr.IsNotNil() {
		sourcePath := sourceAttr.ValueAsStrings()[0]

		// resolve module source path to path relative to cwd
		if strings.HasPrefix(sourcePath, ".") {
			var err error
			sourcePath, err = cleanPathRelativeToWorkingDir(filepath.Dir(b.GetMetadata().Range().GetFilename()), sourcePath)
			if err != nil {
				_, _ = fmt.Fprintf(os.Stderr, "WARNING: did not clean path for module %s due to error(s): %s\n", fmt.Sprintf("%s:%s", b.FullName(), b.GetMetadata().Range().GetFilename()), err)
			}
		}

		for _, requiredSource := range r.RequiredSources {
			if requiredSource == "*" || wildcardMatch(requiredSource, sourcePath) {
				found = true
				break
			}
		}
	}

	return found
}

func cleanPathRelativeToWorkingDir(dir, path string) (string, error) {
	absPath := filepath.Clean(filepath.Join(dir, path))

	wDir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	if !strings.HasSuffix(wDir, "/") {
		wDir = filepath.Join(wDir, "/")
	}

	relPath, err := filepath.Rel(wDir, absPath)
	if err != nil {
		return "", err
	}

	return relPath, nil
}

func wildcardMatch(pattern string, subject string) bool {
	if pattern == "" {
		return false
	}
	parts := strings.Split(pattern, "*")
	var lastIndex int
	for i, part := range parts {
		if part == "" {
			continue
		}
		if i == 0 {
			if !strings.HasPrefix(subject, part) {
				return false
			}
		}
		if i == len(parts)-1 {
			if !strings.HasSuffix(subject, part) {
				return false
			}
		}
		newIndex := strings.Index(subject, part)
		if newIndex < lastIndex {
			return false
		}
		lastIndex = newIndex
	}
	return true
}
