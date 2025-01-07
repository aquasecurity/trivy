# Input Schema

## Overview

Schemas are declarative documents that define the structure, data types and constraints of inputs being scanned. Trivy provides certain schemas out of the box as seen in the explorer [here](https://aquasecurity.github.io/trivy-schemas/). You can also find the source code for the schemas [here](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas).

It is not required to pass in schemas, in order to scan inputs by Trivy but are required if type-checking is needed. 

Checks can be defined with custom schemas that allow inputs to be verified against them. Adding a policy schema
enables Trivy to show more detailed error messages when an invalid input is encountered.

In Trivy we have been able to define a schema for a [Dockerfile](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas)
Without input schemas, a policy would be as follows:

!!! example
    ```
    # METADATA
    package mypackage

    deny {
        input.evil == "foo bar"
    }
    ```

If this policy is run against offending Dockerfile(s), there will not be any issues as the policy will fail to evaluate.
Although the policy's failure to evaluate is legitimate, this should not result in a positive result for the scan.

For instance if we have a policy that checks for misconfigurations in a `Dockerfile`, we could define the
schema as such

!!! example
    ```
    # METADATA
    # schemas:
    # - input: schema["dockerfile"]
    package mypackage
    
    deny {
        input.evil == "foo bar"
    }
    ```

Here `input: schema["dockerfile"]` points to a schema that expects a valid `Dockerfile` as input. An example of this
can be found [here](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/dockerfile.json).

Now if this policy is evaluated against, a more descriptive error will be available to help fix the problem.

```bash
1 error occurred: testpolicy.rego:8: rego_type_error: undefined ref: input.evil
        input.evil
              ^
              have: "evil"
              want (one of): ["Stages"]
```

Currently, out of the box the following schemas are supported natively:

1. [Docker](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/dockerfile.json)
2. [Kubernetes](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/kubernetes.json)
3. [Cloud](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/cloud.json)


## Custom Checks with Custom Schemas

You can also bring a custom policy that defines one or more custom schema. 

!!! example
    ```
    # METADATA
    # schemas:
    # - input: schema["fooschema"]
    # - input: schema["barschema"]
    package mypackage
    
    deny {
        input.evil == "foo bar"
    }
    ```

The checks can be placed in a structure as follows

!!! example
    ```
    /Users/user/my-custom-checks
    ├── my_policy.rego
    └── schemas
        └── fooschema.json
        └── barschema.json
    ```

To use such a policy with Trivy, use the `--config-policy` flag that points to the policy file or to the directory where the schemas and checks are contained.

```bash
$ trivy --config-policy=/Users/user/my-custom-checks <path/to/iac>
```

For more details on how to define schemas within Rego checks, please see the [OPA guide](https://www.openpolicyagent.org/docs/latest/policy-language/#schema-annotations) that describes it in more detail.

### Scan arbitrary JSON and YAML configurations
By default, scanning JSON and YAML configurations is disabled, since Trivy does not contain built-in checks for these configurations. To enable it, pass the `json` or `yaml` to `--misconfig-scanners`. Trivy will pass each file as is to the checks input.


!!! example
```bash
$ cat iac/serverless.yaml
service: serverless-rest-api-with-pynamodb

frameworkVersion: ">=2.24.0"

plugins:
  - serverless-python-requirements
...

$ cat serverless.rego
# METADATA
# title: Serverless Framework service name not starting with "aws-"
# description: Ensure that Serverless Framework service names start with "aws-"
# schemas:
#   - input: schema["serverless-schema"]
# custom:
#   id: SF001
#   severity: LOW
package user.serverless001

deny[res] {
    not startswith(input.service, "aws-")
    res := result.new(
        sprintf("Service name %q is not allowed", [input.service]),
        input.service
    )
}

$ trivy config --misconfig-scanners=json,yaml --config-check ./serverless.rego --check-namespaces user ./iac
serverless.yaml (yaml)

Tests: 4 (SUCCESSES: 3, FAILURES: 1)
Failures: 1 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

LOW: Service name "serverless-rest-api-with-pynamodb" is not allowed
═════════════════════════════════════════════════════════════════════════════════════════════════════════
Ensure that Serverless Framework service names start with "aws-"
```

!!! note
In the case above, the custom check specified has a metadata annotation for the input schema `input: schema["serverless-schema"]`. This allows Trivy to type check the input IaC files provided.

Optionally, you can also pass schemas using the `config-file-schemas` flag. Trivy will use these schemas for file filtering and type checking in Rego checks.

!!! example
```bash
$ trivy config --misconfig-scanners=json,yaml --config-check ./serverless.rego --check-namespaces user --config-file-schemas ./serverless-schema.json ./iac
```

If the `--config-file-schemas` flag is specified Trivy ensures that each input IaC config file being scanned is type-checked against the schema. If the input file does not match any of the passed schemas, it will be ignored.

If the schema is specified in the check metadata and is in the directory specified in the `--config-check` argument, it will be automatically loaded as specified [here](./custom/schema.md#custom-checks-with-custom-schemas), and will only be used for type checking in Rego.

!!! note
If a user specifies the `--config-file-schemas` flag, all input IaC config files are ensured that they pass type-checking. It is not required to pass an input schema in case type checking is not required. This is helpful for scenarios where you simply want to write a Rego check and pass in IaC input for it. Such a use case could include scanning for a new service which Trivy might not support just yet.

!!! tip
It is also possible to specify multiple input schemas with `--config-file-schema` flag as it can accept a comma seperated list of file paths or a directory as input. In the case of multiple schemas being specified, all of them will be evaluated against all the input files.


