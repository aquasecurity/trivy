package iam

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/iam"
)

func ParsePolicyBlock(block *terraform.Block) []iam.Binding {
	var bindings []iam.Binding
	for _, bindingBlock := range block.GetBlocks("binding") {
		binding := iam.Binding{
			Metadata:                      bindingBlock.GetMetadata(),
			Members:                       nil,
			Role:                          bindingBlock.GetAttribute("role").AsStringValueOrDefault("", bindingBlock),
			IncludesDefaultServiceAccount: types.BoolDefault(false, bindingBlock.GetMetadata()),
		}
		membersAttr := bindingBlock.GetAttribute("members")
		for _, member := range membersAttr.ValueAsStrings() {
			binding.Members = append(binding.Members, types.String(member, membersAttr.GetMetadata()))
		}
		bindings = append(bindings, binding)
	}
	return bindings
}
