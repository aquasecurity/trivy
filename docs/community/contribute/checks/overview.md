# Contribute Rego Checks

The following guide provides an overview of contributing checks to the default checks in Trivy. 

All of the checks in Trivy can be found in the [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main) repository on GitHub. Before you begin writing a check, ensure:

1. The check does not already exist as part of the default checks in the [trivy-checks](https://github.com/aquasecurity/trivy-checks/tree/main) repository.
2. The pull requests in the [trivy-checks](https://github.com/aquasecurity/trivy-checks/pulls) repository to see  whether someone else is already contributing the check that you wanted to add. 
3. The [issues in Trivy](https://github.com/aquasecurity/trivy/issues) to see whether any specific checks are missing in Trivy that you can contribute.

If anything is unclear, please [start a discussion](https://github.com/aquasecurity/trivy/discussions/new) and we will do our best to help.

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

## Verify the provider and service exists

Every check for a cloud service references a cloud provider. The list of providers are found in the [Trivy](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) repository. 

Before writing a new check for a cloud provider, you need to verify if the cloud provider or resource type that your check targets is supported by Trivy. If it's not, you'll need to add support for it. Additionally, if the provider that you want to target exists, you need to check whether the service your policy will target is supported. As a reference you can take a look at the AWS provider [here](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/providers/aws/aws.go).

???+ note
    New Kubernetes and Dockerfile checks do not require any additional provider definitions. You can find an example of a Dockerfile check [here](https://github.com/aquasecurity/trivy-checks/blob/main/checks/docker/add_instead_of_copy.rego) and a Kubernetes check [here](https://github.com/aquasecurity/trivy-checks/blob/main/checks/kubernetes/general/CPU_not_limited.rego).


### Add Support for a New Service in an existing Provider

[Please reference the documentation on adding Support for a New Service](./service-support.md).

This guide also showcases how to add new properties for an existing Service.

## Create a new .rego file

The following directory in the trivy-checks repository contains all of our custom checks. Depending on what type of check you want to create, you will need to nest a new `.rego` file in either of the [subdirectories](https://github.com/aquasecurity/trivy-checks/tree/main/checks):

* cloud: All checks related to cloud providers and their services
* docker: Docker specific checks
* kubernetes: Kubernetes specific checks

## Check Package name

Have a look at the existing package names in the [built in checks](https://github.com/aquasecurity/trivy-checks/tree/main/checks). 

The package name should be in the format `builtin.PROVIDER.SERVICE.ID`, e.g. `builtin.aws.rds.aws0176`.

## Generating an ID

Every check has a custom ID that is referenced throughout the metadata of the check to uniquely identify the check. If you plan to contribue your check back into the [trivy-checks](https://github.com/aquasecurity/trivy-checks) repository, it will require a valid ID. 

Running `make id` in the root of the trivy-checks repository will provide you with the next available _ID_ for your rule. 

## Check Schemas

Rego Checks for Trivy can utilise Schemas to map the input to specific objects. The schemas available are listed [here.](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas). 

More information on using the builtin schemas is provided in the [main documentation.](../../../docs/scanner/misconfiguration/custom/schema.md)

## Check Metadata

The metadata is the top section that starts with `# METADATA`, and has to be placed on top of the check. You can copy and paste from another check as a starting point. This format is effectively _yaml_ within a Rego comment, and is [defined as part of Rego itself](https://www.openpolicyagent.org/docs/latest/policy-language/#metadata).

For detailed information on each component of the Check Metadata, please refer to the [main documentation.](../../../docs/scanner/misconfiguration/custom/index.md)

Note that while the Metadata is optional in your own custom checks for Trivy, if you are contributing your check to the Trivy builtin checks, the Metadata section will be required.


## Writing Rego Rules

Rules are defined using _OPA Rego_. You can find a number of examples in the `checks` directory ([Link](https://github.com/aquasecurity/trivy-checks/tree/main/checks)). The [OPA documentation](https://www.openpolicyagent.org/docs/latest/policy-language/) is a great place to start learning Rego. You can also check out the [Rego Playground](https://play.openpolicyagent.org/) to experiment with Rego, and [join the OPA Slack](https://slack.openpolicyagent.org/).


```rego
deny[res] {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
```

The rule should return a result, which can be created using `result.new`. This function does not need to be imported, it is defined internally and provided at runtime. The first argument is the message to display and the second argument is the resource that the issue was detected on.

It is possible to pass any rego variable that references a field of the input document.

## Generate docs

Finally, you'll want to generate documentation for your newly added rule. Please run `make docs` in the [trivy-checks](https://github.com/aquasecurity/trivy-checks) directory to generate the documentation for your new policy and submit a PR for us to take a look at.

## Adding Tests

All Rego checks need to have tests. There are many examples of these in the `checks` directory for each check ([Link](https://github.com/aquasecurity/trivy-checks/tree/main/checks)). More information on how to write tests for Rego checks is provided in the [custom misconfiguration](../../../docs/scanner/misconfiguration/custom/testing.md) section of the docs.

## Example PR

You can see a full example PR for a new rule being added here: [https://github.com/aquasecurity/defsec/pull/1000](https://github.com/aquasecurity/defsec/pull/1000).
