package iam

import (
	"math"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/terraform"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
)

func adaptPasswordPolicy(modules terraform.Modules) iam.PasswordPolicy {

	policy := iam.PasswordPolicy{
		Metadata:             defsecTypes.NewUnmanagedMetadata(),
		ReusePreventionCount: defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
		RequireLowercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		RequireUppercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		RequireNumbers:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		RequireSymbols:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMetadata()),
		MaxAgeDays:           defsecTypes.IntDefault(math.MaxInt, defsecTypes.NewUnmanagedMetadata()),
		MinimumLength:        defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMetadata()),
	}

	passwordPolicies := modules.GetResourcesByType("aws_iam_account_password_policy")
	if len(passwordPolicies) == 0 {
		return policy
	}

	// aws only allows a single password policy resource
	policyBlock := passwordPolicies[0]

	policy.Metadata = policyBlock.GetMetadata()

	if attr := policyBlock.GetAttribute("require_lowercase_characters"); attr.IsNotNil() {
		policy.RequireLowercase = defsecTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireLowercase = defsecTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_uppercase_characters"); attr.IsNotNil() {
		policy.RequireUppercase = defsecTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireUppercase = defsecTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_numbers"); attr.IsNotNil() {
		policy.RequireNumbers = defsecTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireNumbers = defsecTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("require_symbols"); attr.IsNotNil() {
		policy.RequireSymbols = defsecTypes.BoolExplicit(attr.IsTrue(), attr.GetMetadata())
	} else {
		policy.RequireSymbols = defsecTypes.BoolDefault(false, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("password_reuse_prevention"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.ReusePreventionCount = defsecTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.ReusePreventionCount = defsecTypes.IntDefault(0, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("max_password_age"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MaxAgeDays = defsecTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MaxAgeDays = defsecTypes.IntDefault(math.MaxInt, policyBlock.GetMetadata())
	}
	if attr := policyBlock.GetAttribute("minimum_password_length"); attr.IsNumber() {
		value := attr.AsNumber()
		policy.MinimumLength = defsecTypes.IntExplicit(int(value), attr.GetMetadata())
	} else {
		policy.MinimumLength = defsecTypes.IntDefault(0, policyBlock.GetMetadata())
	}

	return policy
}
