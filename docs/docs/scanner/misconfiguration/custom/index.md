# Custom Checks

## Overview
You can write custom checks in [Rego][rego].
Once you finish writing custom checks, you can pass the check files or the directory where those checks are stored with --config-check` option.

``` bash
trivy config --config-check /path/to/policy.rego --config-check /path/to/custom_checks --namespaces user /path/to/config_dir
```

As for `--namespaces` option, the detail is described as below.

### File formats
If a file name matches the following file patterns, Trivy will parse the file and pass it as input to your Rego policy.

| File format   | File pattern                                              |
|---------------|-----------------------------------------------------------|
| JSON          | `*.json`                                                  |
| YAML          | `*.yaml` and `*.yml`                                      |
| Dockerfile    | `Dockerfile`, `Dockerfile.*`, and `*.Dockerfile`          |
| Containerfile | `Containerfile`, `Containerfile.*`, and `*.Containerfile` |
| Terraform     | `*.tf` and `*.tf.json`                                    |

### Configuration languages
In the above general file formats, Trivy automatically identifies the following types of configuration files:

- CloudFormation (JSON/YAML)
- Kubernetes (JSON/YAML)
- Helm (YAML)
- Terraform Plan (JSON/Snapshot)

This is useful for filtering inputs, as described below.

## Rego format
A single package must contain only one policy.

!!!example
    ``` rego
    # METADATA
    # title: Deployment not allowed
    # description: Deployments are not allowed because of some reasons.
    # schemas:
    #   - input: schema["kubernetes"]
    # custom:
    #   id: ID001
    #   severity: LOW
    #   input:
    #     selector: 
    #     - type: kubernetes
    package user.kubernetes.ID001
    
    deny[res] {
        input.kind == "Deployment"
        msg := sprintf("Found deployment '%s' but deployments are not allowed", [input.metadata.name])
        res := result.new(msg, input.kind)
    }
    ```

In this example, ID001 "Deployment not allowed" is defined under `user.kubernetes.ID001`.
If you add a new custom policy, it must be defined under a new package like `user.kubernetes.ID002`.

### Policy structure

`# METADATA` (optional unless the check will be contributed into Trivy)
:   - SHOULD be defined for clarity since these values will be displayed in the scan results
    - `custom.input` SHOULD be set to indicate the input type the policy should be applied to. See [list of available types][source-types]

`package` (required)
:   - MUST follow the Rego's [specification][package]
    - MUST be unique per policy
    - SHOULD include policy id for uniqueness
    - MAY include the group name such as `kubernetes` for clarity
        - Group name has no effect on policy evaluation

`deny` (required)
:   - SHOULD be `deny` or start with `deny_`
        - Although `warn`, `warn_*`, `violation`, `violation_` also work for compatibility, `deny` is recommended as severity can be defined in `__rego_metadata__`.
    - SHOULD return ONE OF:
        - The result of a call to `result.new(msg, cause)`. The `msg` is a `string` describing the issue occurrence, and the `cause` is the property/object where the issue occurred. Providing this allows Trivy to ascertain line numbers and highlight code in the output. 
        - A `string` denoting the detected issue
            - Although `object` with `msg` field is accepted, other fields are dropped and `string` is recommended if `result.new()` is not utilised.
            - e.g. `{"msg": "deny message", "details": "something"}`

### Package
A package name must be unique per policy.

!!!example
    ``` rego
    package user.kubernetes.ID001
    ```

By default, only `builtin.*` packages will be evaluated.
If you define custom packages, you have to specify the package prefix via `--namespaces` option. By default, Trivy only runs in its own namespace, unless specified by the user. Note that the custom namespace does not have to be `user` as in this example. It could be anything user-defined.

``` bash
trivy config --config-check /path/to/custom_checks --namespaces user /path/to/config_dir
```

In this case, `user.*` will be evaluated.
Any package prefixes such as `main` and `user` are allowed.

### Metadata

The check must contain a [Rego Metadata](https://www.openpolicyagent.org/docs/latest/policy-language/#metadata) section. Trivy uses standard rego metadata to define the new policy and general information about it.

Trivy supports extra fields in the `custom` section as described below.

!!!example
    ``` rego
    # METADATA
    # title: Deployment not allowed
    # description: Deployments are not allowed because of some reasons.
    # custom:
    #   id: ID001
    #   severity: LOW
    #   input:
    #     selector:
    #     - type: kubernetes
    ```
  
If you are creating checks for your Trivy misconfiguration scans, some fields are optional as referenced in the table below. The `schemas` field should be used to enable policy validation using a built-in schema. It is recommended to use this to ensure your checks are 
correct and do not reference incorrect properties/values.

| Field name                 | Allowed values                                                    |        Default value         |     In table     |     In JSON      |
|----------------------------|-------------------------------------------------------------------|:----------------------------:|:----------------:|:----------------:|
| title                      | Any characters                                                    |             N/A              | :material-check: | :material-check: |
| description                | Any characters                                                    |                              | :material-close: | :material-check: |
| schemas.input              | `schema["kubernetes"]`, `schema["dockerfile"]`, `schema["cloud"]` | (applied to all input types) | :material-close: | :material-close: |
| custom.id                  | Any characters                                                    |             N/A              | :material-check: | :material-check: |
| custom.severity            | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`                               |           UNKNOWN            | :material-check: | :material-check: |
| custom.recommended_actions | Any characters                                                    |                              | :material-close: | :material-check: |
| custom.deprecated          | `true`, `false`                                                   |           `false`            | :material-close: | :material-check: | 
| custom.input.selector.type | Any item(s) in [this list][source-types]                          |                              | :material-close: | :material-check: |
| url                        | Any characters                                                    |                              | :material-close: | :material-check: |

#### custom.avd_id and custom.id

The AVD_ID can be used to link the check to the Aqua Vulnerability Database (AVD) entry. For example, the `avd_id` `AVD-AWS-0176` is the ID of the check in the [AWS Vulnerability Database](https://avd.aquasec.com/). If you are [contributing your check to trivy-checks](../../../../community/contribute/checks/overview.md), you need to generate an ID using `make id` in the [trivy-checks](https://github.com/aquasecurity/trivy-checks) repository. The output of the command will provide you the next free IDs for the different providers in Trivy.

The ID is based on the AVD_ID. For instance if the `avd_id` is `AVD-AWS-0176`, the ID is `ID0176`.

#### custom.provider

The `provider` field references the [provider](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) available in Trivy. This should be the same as the provider name in the `pkg/iac/providers` directory, e.g. `aws`. 

#### custom.service

Services are defined within a provider. For instance, RDS is a service and AWS is a provider. This should be the same as the service name in one of the provider directories. ([Link](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers)), e.g. `aws/rds`.

#### custom.input

The `input` tells Trivy what inputs this check should be applied to. Cloud provider checks should always use the `selector` input, and should always use the `type` selector with `cloud`. Check targeting Kubernetes yaml can use `kubenetes`, RBAC can use `rbac`, and so on.

#### Subtypes in the custom data

Subtypes currently only need to be defined for cloud providers [as detailed in the documentation.](./selectors.md/#enabling-selectors-and-subtypes)

#### Scan Result

Some fields are displayed in scan results.

``` bash
k.yaml (kubernetes)
───────────────────

Tests: 32 (SUCCESSES: 31, FAILURES: 1)
Failures: 1 (UNKNOWN: 0, LOW: 1, MEDIUM: 0, HIGH: 0, CRITICAL: 0)

LOW: Found deployment 'my-deployment' but deployments are not allowed
════════════════════════════════════════════════════════════════════════
Deployments are not allowed because of some reasons.
────────────────────────────────────────────────────────────────────────
 k.yaml:1-2
────────────────────────────────────────────────────────────────────────
   1 ┌ apiVersion: v1
   2 └ kind: Deployment
────────────────────────────────────────────────────────────────────────
```

### Input
You can specify input format via the `custom.input` annotation.

!!!example
    ``` rego
    # METADATA
    # custom:
    #   input:
    #     combine: false
    #     selector:
    #     - type: kubernetes
    ```

`combine` (boolean)
: The details are [here](combine.md).

`selector` (array)
:   This option filters the input by file format or configuration language. 
    In the above example, Trivy passes only Kubernetes files to this policy.
    Even if a Dockerfile exists in the specified directory, it will not be passed to the policy as input.

    Possible values for input types are:

    - `dockerfile` (Dockerfile)
    - `kubernetes` (Kubernetes YAML/JSON)
    - `rbac` (Kubernetes RBAC YAML/JSON)
    - `cloud` (Cloud format, as defined by Trivy - this is used for Terraform, CloudFormation, and Cloud/AWS scanning)
    - `yaml` (Generic YAML)
    - `json` (Generic JSON)
    - `toml` (Generic TOML)

    When configuration languages such as Kubernetes are not identified, file formats such as JSON will be used as `type`.
    When a configuration language is identified, it will overwrite `type`.
    
    !!! example
        `pod.yaml` including Kubernetes Pod will be handled as `kubernetes`, not `yaml`.
        `type` is overwritten by `kubernetes` from `yaml`.

    `type` accepts `kubernetes`, `dockerfile`, `cloudformation`, `terraform`, `terraformplan`, `json`, or `yaml`.

### Schemas
See [here](schema.md) for the detail.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[package]: https://www.openpolicyagent.org/docs/latest/policy-language/#packages
[source-types]: https://github.com/aquasecurity/trivy/blob/9361cdb7e28fd304d6fd2a1091feac64a6786672/pkg/iac/types/sources.go#L4
