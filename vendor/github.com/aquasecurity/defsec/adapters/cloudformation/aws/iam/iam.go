package iam

import (
	"github.com/aquasecurity/defsec/parsers/cloudformation/parser"
	"github.com/aquasecurity/defsec/providers/aws/iam"
)

// Adapt ...
func Adapt(cfFile parser.FileContext) (result iam.IAM) {

	result.Policies = getPolicies(cfFile)
	result.Roles = getRoles(cfFile)
	result.Users = getUsers(cfFile)
	result.Groups = getGroups(cfFile)
	return result

}
