package iam

import (
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scanners/cloudformation/parser"
	"github.com/liamg/iamgo"
)

func getPolicies(ctx parser.FileContext) (policies []iam.Policy) {
	for _, policyResource := range ctx.GetResourcesByType("AWS::IAM::Policy") {
		policyProp := policyResource.GetProperty("PolicyDocument")
		policyName := policyResource.GetStringProperty("PolicyName")

		doc, err := iamgo.Parse(policyProp.GetJsonBytes())
		if err != nil {
			continue
		}

		policies = append(policies, iam.Policy{
			Metadata: policyProp.Metadata(),
			Name:     policyName,
			Document: iam.Document{
				Metadata: policyProp.Metadata(),
				Parsed:   *doc,
			},
		})
	}
	return policies
}

func getRoles(ctx parser.FileContext) (roles []iam.Role) {
	for _, roleResource := range ctx.GetResourcesByType("AWS::IAM::Role") {
		policyProp := roleResource.GetProperty("Policies")
		roleName := roleResource.GetStringProperty("RoleName")

		roles = append(roles, iam.Role{
			Metadata: roleResource.Metadata(),
			Name:     roleName,
			Policies: getPoliciesDocs(policyProp),
		})
	}
	return roles
}

func getUsers(ctx parser.FileContext) (users []iam.User) {
	for _, userResource := range ctx.GetResourcesByType("AWS::IAM::User") {
		policyProp := userResource.GetProperty("Policies")
		userName := userResource.GetStringProperty("GroupName")

		users = append(users, iam.User{
			Metadata: userResource.Metadata(),
			Name:     userName,
			Policies: getPoliciesDocs(policyProp),
		})
	}
	return users
}

func getGroups(ctx parser.FileContext) (groups []iam.Group) {
	for _, groupResource := range ctx.GetResourcesByType("AWS::IAM::Group") {
		policyProp := groupResource.GetProperty("Policies")
		groupName := groupResource.GetStringProperty("GroupName")

		groups = append(groups, iam.Group{
			Metadata: groupResource.Metadata(),
			Name:     groupName,
			Policies: getPoliciesDocs(policyProp),
		})
	}
	return groups
}

func getPoliciesDocs(policiesProp *parser.Property) []iam.Policy {
	var policies []iam.Policy

	for _, policy := range policiesProp.AsList() {
		policyProp := policy.GetProperty("PolicyDocument")
		policyName := policy.GetStringProperty("PolicyName")

		doc, err := iamgo.Parse(policyProp.GetJsonBytes())
		if err != nil {
			continue
		}

		policies = append(policies, iam.Policy{
			Metadata: policyProp.Metadata(),
			Name:     policyName,
			Document: iam.Document{
				Metadata: policyProp.Metadata(),
				Parsed:   *doc,
			},
		})
	}
	return policies
}
