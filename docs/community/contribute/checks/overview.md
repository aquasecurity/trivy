# Contribute Rego Checks

The following guide provides an overview of contributing checks to the default checks in Trivy. 

All of the checks in Trivy can be found in the [trivy-policies](https://github.com/aquasecurity/trivy-policies/tree/main) repository on GitHub. Before you beging writing a check, ensure:

1. The check does not already exist as part of the default checks in the [trivy-policies](https://github.com/aquasecurity/trivy-policies/tree/main) repository.
2. The pull requests in the [trivy-policies](https://github.com/aquasecurity/trivy-policies/pulls) repository to see  whether someone else is already contributing the check that you wanted to add. 
3. The [issues in Trivy](https://github.com/aquasecurity/trivy/issues) to see whether any specific checks are missing in Trivy.

If anything is unclear, please [start a discussion](https://github.com/aquasecurity/trivy/discussions/new) and we'll do our best to help.

## Check structure

Checks are written in Rego and follow a particular structure in Trivy. Below is an example check for AWS:

```rego
# METADATA
# title: "RDS IAM Database Authentication Disabled"
# description: "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
# - input: schema["aws"]
# related_resources:
# - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   id: AVD-AWS-0176
#   avd_id: AVD-AWS-0176
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   short_code: enable-iam-auth
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
#   input:
#     selector:
#     - type: cloud
#       subtypes:
#         - service: rds
#           provider: aws

package builtin.aws.rds.aws0176

deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

## Adding a new provider or service

Every check references a provider. The list of providers are found in the [trivy](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) repository. 

Before writing a new check, you need to verify if the provider your check targets is supported by Trivy. If it's not, you'll need to add support for it. Additionally, if the provider that you want to target exists, you need to check whether the service your policy will target is supported.

### Add Support for a New Cloud Provider

[Please reference the documentation on adding Support for a New Cloud Provider](./provider-support.md).

### Add Support for a New Service in an existing Provider

[Please reference the documentation on adding Support for a New Service](./service-support.md).

This guide also showcases how to add new properties for an existing Service.

## Check Metadata

The metadata is the top section that starts with `# METADATA`, and has to be placed on top of the check. You can copy and paste from another check as a starting point. This format is effectively _yaml_ within a Rego comment, and is [defined as part of Rego itself](https://www.openpolicyagent.org/docs/latest/policy-language/#metadata).

The metadata consists of the following fields:

- `title` is a title for the rule. The title should clearly and succinctly state the problem which is being detected.
- `description` is a description of the problem which is being detected. The description should be a little more verbose than the title, and should describe what the rule is trying to achieve. Imagine it completing a sentence starting with `You should...`.
- `scope` is used to define the scope of the policy. In this case, we are defining a check that applies to the entire package. At the moment, Trivy only supports using package scope for metadata, so this should always be set to `package`.
- `schemas` tells Rego that it should use the `AWS` schema to validate the use of the input data in the policy. We currently support [the following shemas](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas). Please choose a schema that is applicable to your check. Using a schema can help you validate your policy faster for syntax issues.
- `custom` is used to define custom fields that can be used by Trivy to provide additional context to the policy and any related detections. This can contain the following:
    - `avd_id` can be used to link the check to the AVD entry. In the example check above, the `avd_id` `AVD-AWS-0176` is the ID of the check in the [AWS Vulnerability Database](https://avd.aquasec.com/). If there is no AVD_ID available, you need to generate an ID to use for this field using `make id`.
    - `provider` is the name of the [provider](https://github.com/aquasecurity/defsec/tree/master/pkg/providers) the check targets. This should be the same as the provider name in the `pkg/providers` directory, e.g. `aws`.
    - `service` is the name of the service by the provider that the check targets. This should be the same as the service name in the `pkg/providers` directory, e.g. `rds`.
    - `severity` is the severity of the check. This should be one of `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`.
    - `short_code` is a short code for the check. This should be a short, descriptive name for the check, separating words with hyphens. You should omit provider/service from this.
    - `recommended_action` is a recommended remediation action for the check. This should be a short, descriptive sentence describing what the user should do to resolve the issue.
    - `input` tells trivy what inputs this check should be applied to. Cloud provider checks should always use the `selector` input, and should always use the `type` selector with `cloud`. Check targeting Kubernetes yaml can use `kubenetes`, RBAC can use `rbac`, and so on.
    - `subtypes` aid the engine to determine if it should load this policy or not for scanning. This can aid with the performance of scanning, especially if you have a lot of checks but not all apply to the IaC that you are trying to scan.

### Generating an ID

If you plan to contribue your check back into the [trivy-policies](https://github.com/aquasecurity/trivy-policies) repository, it will require a valid ID. 

Running `make id` in the trivy-policies repository will provide you with the next available _ID_ for your rule. The ID is used in the Rego check to identify it.

## Writing Rego Rules

At last, it's time to write your rule code! Rules are defined using _OPA Rego_. You can find a number of examples in the `checks/cloud` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/checks/cloud)). The [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) is a great place to start learning Rego. You can also check out the [Rego Playground](https://play.openpolicyagent.org/) to experiment with Rego, and [join the OPA Slack](https://slack.openpolicyagent.org/).

Create a new file in `checks/cloud` ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/checks/cloud)) with the name of your rule. You should nest it in the existing directory structure as applicable. The package name should be in the format `builtin.PROVIDER.SERVICE.ID`, e.g. `builtin.aws.rds.aws0176`.

Now you'll need to write the rule logic. This is the code that will be executed to detect the issue. You should define a rule named `deny` and place your code inside this. Every check in Trivy needs to have a `deny` rule.

```rego
deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

The rule should return a result, which can be created using `result.new` (this function does not need to be imported, it is defined internally and provided at runtime). The first argument is the message to display, and the second argument is the resource that the issue was detected on.

In the example above, you'll notice properties are being accessed from the `input.aws` object. The full set of schemas containing all of these properties is [available here](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas). You can match the schema name to the type of input you want to scan.

You should also write a test for your rule(s). There are many examples of these in the `checks/cloud` directory ([Link](https://github.com/aquasecurity/trivy-policies/tree/main/checks/cloud)). More information on how to write tests for Rego checks is provided in the [custom misconfiguration](../../../docs/scanner/misconfiguration/custom/testing.md) section of the docs.

## Generate docs

Finally, you'll want to generate documentation for your newly added rule. Please run `make docs` to generate the documentation for your new policy and submit a PR for us to take a look at.

## Example PR

You can see a full example PR for a new rule being added here: [https://github.com/aquasecurity/defsec/pull/1000](https://github.com/aquasecurity/defsec/pull/1000).
