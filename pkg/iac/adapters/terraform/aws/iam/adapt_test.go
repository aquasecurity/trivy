package iam

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLines(t *testing.T) {
	src := `
	resource "aws_iam_account_password_policy" "strict" {
		minimum_password_length        = 8
		require_lowercase_characters   = true
		require_numbers                = true
		require_uppercase_characters   = true
		require_symbols                = true
	  }

	resource "aws_iam_group" "my_developers" {
		name = "developers"
		path = "/users/"
	  }

	  resource "aws_iam_group_policy" "my_developer_policy" {
		name  = "my_developer_policy"
		group = aws_iam_group.my_developers.name

		policy = <<EOF
		{
		  "Version": "2012-10-17",
		  "Statement": [
		  {
			"Sid": "new policy",
			"Effect": "Allow",
			"Resource": "*",
			"Action": [
				"ec2:Describe*"
			]
		  }
		  ]
		}
		EOF
	  }

	  resource "aws_iam_user" "lb" {
		name = "loadbalancer"
		path = "/system/"
	  }

	  resource "aws_iam_user_policy" "policy" {
		name = "test"
		user = aws_iam_user.lb.name


		policy = jsonencode({
			Version = "2012-10-17"
			Statement = [
			  {
				Action = [
				  "ec2:Describe*",
				]
				Effect   = "Allow"
				Resource = "*"
			  },
			]
		  })
	  }
	`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Groups, 1)
	require.Len(t, adapted.Users, 1)

	group := adapted.Groups[0]
	user := adapted.Users[0]
	policy := adapted.PasswordPolicy

	assert.Equal(t, 2, policy.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, policy.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, policy.MinimumLength.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, policy.MinimumLength.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, policy.RequireLowercase.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, policy.RequireLowercase.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, policy.RequireNumbers.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, policy.RequireNumbers.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, policy.RequireUppercase.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, policy.RequireUppercase.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, policy.RequireSymbols.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, policy.RequireSymbols.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, group.Metadata.Range().GetStartLine())
	assert.Equal(t, 13, group.Metadata.Range().GetEndLine())

	assert.Equal(t, 11, group.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, group.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, group.Policies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 34, group.Policies[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 16, group.Policies[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, group.Policies[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, group.Policies[0].Document.Metadata.Range().GetStartLine())
	assert.Equal(t, 33, group.Policies[0].Document.Metadata.Range().GetEndLine())

	assert.Equal(t, 36, user.Metadata.Range().GetStartLine())
	assert.Equal(t, 39, user.Metadata.Range().GetEndLine())

	assert.Equal(t, 37, user.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 37, user.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 41, user.Policies[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 58, user.Policies[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 42, user.Policies[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, user.Policies[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 46, user.Policies[0].Document.Metadata.Range().GetStartLine())
	assert.Equal(t, 57, user.Policies[0].Document.Metadata.Range().GetEndLine())
}
