package iam

import (
	"math"

	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/parsers/terraform"

	"github.com/aquasecurity/defsec/providers/aws/iam"
)

func adaptPasswordPolicy(modules terraform.Modules) iam.PasswordPolicy {

	policy := iam.PasswordPolicy{
		Metadata:             types.NewUnmanagedMetadata(),
		ReusePreventionCount: types.IntDefault(0, types.NewUnmanagedMetadata()),
		RequireLowercase:     types.BoolDefault(false, types.NewUnmanagedMetadata()),
		RequireUppercase:     types.BoolDefault(false, types.NewUnmanagedMetadata()),
		RequireNumbers:       types.BoolDefault(false, types.NewUnmanagedMetadata()),
		RequireSymbols:       types.BoolDefault(false, types.NewUnmanagedMetadata()),
		MaxAgeDays:           types.IntDefault(math.MaxInt, types.NewUnmanagedMetadata()),
		MinimumLength:        types.IntDefault(0, types.NewUnmanagedMetadata()),
	}

	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	policy.Metadata = policyBlock.GetMetadata()

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = types.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireLowercase = types.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = types.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireUppercase = types.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = types.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireNumbers = types.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = types.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireSymbols = types.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.ReusePreventionCount = types.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.ReusePreventionCount = types.IntDefault(0, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.MaxAgeDays = types.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MaxAgeDays = types.IntDefault(math.MaxInt, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value, _ := attr.Value().AsBigFloat().Float64()
		policy.MinimumLength = types.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MinimumLength = types.IntDefault(0, policyBlock.GetMetadata())
	}

	return policy
}
