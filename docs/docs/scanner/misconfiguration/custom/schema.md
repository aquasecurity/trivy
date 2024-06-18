# Input Schema

## Overview
Checks can be defined with custom schemas that allow inputs to be verified against them. Using check with schema allows Trivy to show more detailed error messages when invalid input is encountered.

In Trivy, we have been able to define a schema for a [Dockerfile](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/rego/schemas). Without input schemas, a check would be as follows:

!!! example
    ```
    # METADATA
    package mypackage

    deny {
        input.evil == "foo bar"
    }
    ```

If this check is run against offending Dockerfile(s), there will not be any issues as the check will fail to evaluate.
Although the check's failure to evaluate is legitimate, this should not result in a positive result for the scan.

For instance, if we have a check that checks for misconfigurations in a `Dockerfile`, we could define the schema as such:

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

Here `input: schema["dockerfile"]` points to a schema that expects a valid `Dockerfile` as input. An example of this can be found [here](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/rego/schemas/dockerfile.json).

Now if this check is evaluated against, a more descriptive error will be available to help fix the problem.

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

You can also bring a custom check that uses one or more custom schemas. 

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

The checks and schemas can be placed in a structure as follows:

!!! example
    ```
    /Users/user/my-custom-checks
    ├── my_policy.rego
    └── schemas
        └── fooschema.jsonschema
        └── barschema.jsonschema
    ```

To use such a check with Trivy, use the `--config-check` flag that points to the check file or to the directory where the schemas and checks are contained. Trivy will automatically detect and load schemas in a directory or subdirectories near the checks.

```bash
$ trivy --config-check=/Users/user/my-custom-checks <path/to/iac>
```

!!! note
    The extension of the schema file must be `.jsonschema`.

For more details on how to define schemas within Rego checks, please see the [OPA guide](https://www.openpolicyagent.org/docs/latest/policy-language/#schema-annotations) that describes it in more detail.