# Input Schema

## Overview

Schemas are declarative documents that define the structure, data types and constraints of inputs being scanned. Trivy provides certain schemas out of the box as seen in the explorer [here](https://aquasecurity.github.io/trivy-schemas/). You can also find the source code for the schemas [here](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas).

It is not required to pass in schemas, in order to scan inputs by Trivy but are required if type-checking is needed. 

Checks can be defined with custom schemas that allow inputs to be verified against them. Adding an input schema
enables Trivy to show more detailed error messages when an invalid input is encountered.

## Unified Schema

One of the unique advantages of Trivy is to take a variety of inputs, such as IaC files (e.g. CloudFormation, Terraform etc.) and also live cloud scanning
(e.g. [Trivy AWS plugin](https://github.com/aquasecurity/trivy-aws)) and normalize them into a standard structure, as defined by the schema.

An example of such an application would be scanning AWS resources. You can scan them prior to deployment via the Trivy misconfiguration scanner and also 
scan them after they've been deployed in the cloud with Trivy AWS scanning. Both scan methods should yield the same result as resources are gathered into 
a unified representation as defined by the [Cloud schema](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/cloud.json). 


## Supported Schemas
Currently out of the box the following schemas are supported natively:

1. [Docker](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/dockerfile.json)
2. [Kubernetes](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/kubernetes.json)
3. [Cloud](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/cloud.json)
4. [Terraform Raw Format](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/terraform-raw.json)

You can interactively view these schemas with the [Trivy Schema Explorer](https://aquasecurity.github.io/trivy-schemas/)


## Example
As mentioned earlier, amongst other built-in schemas, Trivy offers a built-in schema for scanning Dockerfiles. It is available [here](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas)
Without input schemas, a check would be as follows:

!!! example
    ```
    # METADATA
    package mypackage

    deny {
        input.evil == "foo bar"
    }
    ```

If this check is run against an offending Dockerfile(s), there will not be any issues as the check will fail to evaluate.
Although the check's failure to evaluate is legitimate, this should not result in a positive result for the scan.

For instance if we have a check that checks for misconfigurations in a `Dockerfile`, we could define the
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

Now if this check is evaluated against, a more descriptive error will be available to help fix the problem.

```bash
1 error occurred: testcheck.rego:8: rego_type_error: undefined ref: input.evil
        input.evil
              ^
              have: "evil"
              want (one of): ["Stages"]
```


## Custom Checks with Custom Schemas

You can also bring a custom check that defines one or more custom schema. 

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
    ├── my_check.rego
    └── schemas
        └── fooschema.json
        └── barschema.json
    ```

To use such a check with Trivy, use the `--config-check` flag that points to the check file or to the directory where the schemas and checks are contained.

```bash
$ trivy --config-check=/Users/user/my-custom-checks <path/to/iac>
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

If the schema is specified in the check metadata and is in the directory specified in the `--config-check` argument, it will be automatically loaded as specified [here](./schema.md#custom-checks-with-custom-schemas), and will only be used for type checking in Rego.

!!! note
    If a user specifies the `--config-file-schemas` flag, all input IaC config files are ensured that they pass type-checking. It is not required to pass an input schema in case type checking is not required. This is helpful for scenarios where you simply want to write a Rego check and pass in IaC input for it. Such a use case could include scanning for a new service which Trivy might not support just yet.

!!! tip
    It is also possible to specify multiple input schemas with `--config-file-schema` flag as it can accept a comma-separated list of file paths or a directory as input. In the case of multiple schemas being specified, all of them will be evaluated against all the input files.


