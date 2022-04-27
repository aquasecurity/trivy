package custom

import (
	"fmt"

	"github.com/aquasecurity/defsec/parsers/terraform"
)

func checkTags(block *terraform.Block, spec *MatchSpec, customCtx *customContext) bool {
	expectedTag := fmt.Sprintf("%v", spec.MatchValue)

	if block.HasChild("tags") {
		tagsBlock := block.GetAttribute("tags")
		if tagsBlock.Contains(expectedTag) {
			return true
		}
	}

	var alias string
	if block.HasChild("provider") {
		aliasRef := block.GetAttribute("provider").AllReferences()
		if len(aliasRef) > 0 {
			alias = aliasRef[0].String()
		}
	}

	awsProviders := customCtx.module.GetProviderBlocksByProvider("aws", alias)
	for _, providerBlock := range awsProviders {
		if providerBlock.HasChild("default_tags") {
			defaultTags := providerBlock.GetBlock("default_tags")
			if defaultTags.HasChild("tags") {
				tags := defaultTags.GetAttribute("tags")
				if tags.Contains(expectedTag) {
					return true
				}
			}
		}
	}
	return false
}

func ofType(block *terraform.Block, spec *MatchSpec) bool {
	switch value := spec.MatchValue.(type) {
	case []interface{}:
		for _, v := range value {
			if block.TypeLabel() == v {
				return true
			}
		}
	}

	return false
}
