package iam

import (
	"math"

	defsecTypes "github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy/pkg/terraform"

	"github.com/aquasecurity/trivy/pkg/providers/aws/iam"
)

func adaptPasswordPolicy(modules terraform.Modules) iam.PasswordPolicy {

	policy := iam.PasswordPolicy{
		Metadata:             defsecTypes.NewUnmanagedMisconfigMetadata(),
		ReusePreventionCount: defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMisconfigMetadata()),
		RequireLowercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
		RequireUppercase:     defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
		RequireNumbers:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
		RequireSymbols:       defsecTypes.BoolDefault(false, defsecTypes.NewUnmanagedMisconfigMetadata()),
		MaxAgeDays:           defsecTypes.IntDefault(math.MaxInt, defsecTypes.NewUnmanagedMisconfigMetadata()),
		MinimumLength:        defsecTypes.IntDefault(0, defsecTypes.NewUnmanagedMisconfigMetadata()),
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
