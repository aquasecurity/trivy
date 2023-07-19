# Input Schema

## Overview
Policies can be defined with custom schemas that allow inputs to be verified against them. Adding a policy schema
enables Trivy to show more detailed error messages when an invalid input is encountered.

In Trivy we have been able to define a schema for a [Dockerfile](https://github.com/aquasecurity/defsec/blob/master/pkg/rego/schemas/dockerfile.json).
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
can be found [here](https://github.com/aquasecurity/defsec/blob/master/pkg/rego/schemas/dockerfile.json)

Now if this policy is evaluated against, a more descriptive error will be available to help fix the problem.

```bash
1 error occurred: testpolicy.rego:8: rego_type_error: undefined ref: input.evil
        input.evil
              ^
              have: "evil"
              want (one of): ["Stages"]
```

Currently, out of the box the following schemas are supported natively:

1. [Docker](https://github.com/aquasecurity/defsec/blob/master/pkg/rego/schemas/dockerfile.json)
2. [Kubernetes](https://github.com/aquasecurity/defsec/blob/master/pkg/rego/schemas/kubernetes.json)
3. [Cloud](https://github.com/aquasecurity/defsec/blob/master/pkg/rego/schemas/cloud.json)


## Custom Policies with Custom Schemas

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

The policies can be placed in a structure as follows

!!! example
    ```
    /Users/user/my-custom-policies
    ├── my_policy.rego
    └── schemas
        └── fooschema.json
        └── barschema.json
    ```

To use such a policy with Trivy, use the `--config-policy` flag that points to the policy file or to the directory where the schemas and policies are contained.

```bash
$ trivy --config-policy=/Users/user/my-custom-policies <path/to/iac>
```

For more details on how to define schemas within Rego policies, please see the [OPA guide](https://www.openpolicyagent.org/docs/latest/schemas/#schema-annotations) that describes it in more detail.