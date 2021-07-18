# Custom Policies

## Overview
You can write custom policies in [Rego][rego].
Once you finish writing custom policies, you can pass the directory where those policies are stored with `--policy` option.

``` bash
trivy conf --policy /path/to/custom_policies --namespaces user /path/to/config_dir
```

As for `--namespaces` option, the detail is described as below.

### File formats
If a file name matches the following file patterns, Trivy will parse the file and pass it as input to your Rego policy.

| File format    | File pattern                                     |
| -------------- | ------------------------------------------------ |
| JSON           | `*.json`                                         |
| YAML           | `*.yaml`                                         |
| TOML           | `*.toml`                                         |
| HCL            | `*.hcl`, `*.hcl1`, and `*.hcl2`                  |
| Dockerfile     | `Dockerfile`, `Dockerfile.*`, and `*.Dockerfile` |

### Configuration languages
In the above general file formats, Trivy automatically identifies the following types of configuration files:

- Ansible (YAML)
- CloudFormation (JSON/YAML)
- Kubernetes (JSON/YAML)

This is useful for filtering inputs, as described below.

!!! warning
    Custom policies do not support Terraform at the moment.

## Rego format
A single package must contain only one policy.

!!!example
    ``` rego
    package user.kubernetes.ID001
    
    __rego_metadata__ := {
    	"id": "ID001",
    	"title": "Deployment not allowed",
    	"severity": "LOW",
    	"type": "Custom Kubernetes Check",
    	"description": "Deployments are not allowed because of some reasons.",
    }

    __rego_input__ := {
        "selector": [
            {"type": "kubernetes"},
        ],
    }
    
    deny[msg] {
    	input.kind == "Deployment"
    	msg = sprintf("Found deployment '%s' but deployments are not allowed", [input.metadata.name])
    }
    ```

In this example, ID001 "Deployment not allowed" is defined under `user.kubernetes.ID001`.
If you add a new custom policy, it must be defined under a new package like `user.kubernetes.ID002`.

### Policy structure

`package` (required)
:   - MUST follow the Rego's [specification][package]
    - MUST be unique per policy
    - SHOULD include policy id for uniqueness
    - MAY include the group name such as `kubernetes` for clarity
        - Group name has no effect on policy evaluation

`__rego_metadata__` (optional)
:   - SHOULD be defined for clarity since these values will be displayed in the scan results

`__rego_input__` (optional)
:   - MAY be defined when you want to specify input format

`deny` (required)
:   - SHOULD be `deny` or start with `deny_`
        - Although `warn`, `warn_*`, `violation`, `violation_` also work for compatibility, `deny` is recommended as severity can be defined in `__rego_metadata__`.
    - SHOULD return `string`
        - Although `object` with `msg` field is accepted, other fields are dropped and `string` is recommended.
        - e.g. `{"msg": "deny message", "details": "something"}`
    

### Package
A package name must be unique per policy.

!!!example
    ``` rego
    package user.kubernetes.ID001
    ```

By default, only `appshield.*` packages will be evaluated.
If you define custom packages, you have to specify the package prefix via `--namespaces` option. 

``` bash
trivy conf --policy /path/to/custom_policies --namespaces user /path/to/config_dir
```

In this case, `user.*` will be evaluated.
Any package prefixes such as `main` and `user` are allowed.

### Metadata
Metadata helps enrich Trivy's scan results with useful information.

!!!example
    ``` rego
    __rego_metadata__ := {
    	"id": "ID001",
    	"title": "Deployment not allowed",
    	"severity": "LOW",
    	"type": "Custom Kubernetes Check",
    	"description": "Deployments are not allowed because of some reasons.",
    	"recommended_actions": "Remove Deployment",
    	"url": "https://cloud.google.com/blog/products/containers-kubernetes/kubernetes-best-practices-resource-requests-and-limits",
    }
    ```
  
All fields under `__rego_metadata__` are optional.

| Field name         | Allowed values                      | Default value | In table           | In JSON          |
| ------------------ | ------------------------------------| :-----------: | :----------------: |:---------------: |
| id                 | Any characters                      | N/A           | :material-check:   | :material-check: |
| title              | Any characters                      | N/A           | :material-check:   | :material-check: |
| severity           | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | UNKNOWN       | :material-check:   | :material-check: |
| type               | Any characters                      | N/A           | :material-check:   | :material-check: |
| description        | Any characters                      |               | :material-close:   | :material-check: |
| recommended_actions| Any characters                      |               | :material-close:   | :material-check: | 
| url                | Any characters                      |               | :material-close:   | :material-check: |

Some fields are displayed in scan results.

``` bash
deployment.yaml (kubernetes)
============================
Tests: 28 (SUCCESSES: 14, FAILURES: 14, EXCEPTIONS: 0)
Failures: 14 (HIGH: 1)

+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |                CHECK                | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
| Custom Kubernetes Check   |   ID001    | Deployment not allowed              |   LOW    | Found deployment 'test' but deployments  |
|                           |            |                                     |          | are not allowed                          |
+---------------------------+------------+-------------------------------------+----------+------------------------------------------+
```

### Input
You can specify input format via `__rego_input__`.
All fields under `__rego_input` are optional.

!!!example
    ``` rego
    __rego_input__ := {
        "combine": false,
        "selector": [
            {"type": "kubernetes"},
        ],
    }
    ```

`combine` (boolean)
: The details is [here](combine.md).

`selector` (array)
:   This option filters the input by file formats or configuration languages. 
    In the above example, Trivy passes only Kubernetes files to this policy.
    Even if Dockerfile exists in the specified directory, it will not be passed to the policy as input.

    When configuration language such as Kubernetes is not identified, file format such as JSON will be used as `type`.
    When configuration language is identified, it will overwrite `type`.
    
    !!! example
        `pod.yaml` including Kubernetes Pod will be handled as `kubernetes`, not `yaml`.
        `type` is overwritten by `kubernetes` from `yaml`.

    `type` accepts `kubernetes`, `dockerfile`, `ansible`, `cloudformation`, `json`, `yaml`, `toml`, or `hcl`.

[rego]: https://www.openpolicyagent.org/docs/latest/policy-language/
[package]: https://www.openpolicyagent.org/docs/latest/policy-language/#packages
