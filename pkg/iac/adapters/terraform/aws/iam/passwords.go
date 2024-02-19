package iam

import (
	"math"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptPasswordPolicy(modules terraform.Modules) iam.PasswordPolicy {

	policy := iam.PasswordPolicy{
		Metadata:             iacTypes.NewUnmanagedMetadata(),
		ReusePreventionCount: iacTypes.IntDefault(0, iacTypes.NewUnmanagedMetadata()),
		RequireLowercase:     iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		RequireUppercase:     iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		RequireNumbers:       iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		RequireSymbols:       iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		MaxAgeDays:           iacTypes.IntDefault(math.MaxInt, iacTypes.NewUnmanagedMetadata()),
		MinimumLength:        iacTypes.IntDefault(0, iacTypes.NewUnmanagedMetadata()),
	}

	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	policy.Metadata = policyBlock.GetMetadata()

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = iacTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireLowercase = iacTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = iacTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireUppercase = iacTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = iacTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireNumbers = iacTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = iacTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireSymbols = iacTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.ReusePreventionCount = iacTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.ReusePreventionCount = iacTypes.IntDefault(0, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MaxAgeDays = iacTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MaxAgeDays = iacTypes.IntDefault(math.MaxInt, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MinimumLength = iacTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MinimumLength = iacTypes.IntDefault(0, policyBlock.GetMetadata())
	}

	return policy
}
