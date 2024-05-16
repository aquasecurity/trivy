# Exceptions
Exceptions let you specify cases where you allow policy violations.
Trivy supports two types of exceptions.

!!! info
    Exceptions can be applied to built-in checks as well as custom checks.

## Namespace-based exceptions
There are some cases where you need to disable built-in checks partially or fully.
Namespace-based exceptions lets you rough choose which individual packages to exempt.

To use namespace-based exceptions, create a Rego rule with the name `exception` that returns the package names to exempt.
The `exception` rule must be defined under `namespace.exceptions`.
`data.namespaces` includes all package names.


!!! example
    ``` rego
    package namespace.exceptions

    import data.namespaces
        
    exception[ns] {
        ns := data.namespaces[_]
        startswith(ns, "builtin.kubernetes")
    }
    ```

This example exempts all built-in checks for Kubernetes.

## Rule-based exceptions
There are some cases where you need more flexibility and granularity in defining which cases to exempt.
Rule-based exceptions lets you granularly choose which individual rules to exempt, while also declaring under which conditions to exempt them.

To use rule-based exceptions, create a Rego rule with the name `exception` that returns the rule name suffixes to exempt, prefixed by `deny_` (for example, returning `foo` will exempt `deny_foo`). 
The rule can make any other assertion, for example, on the input or data documents. 
This is useful to specify the exemption for a specific case.

Note that if you specify the empty string, the exception will match all rules named `deny`.

```
exception[rules] {
    # Logic

    rules = ["foo","bar"]
}
```

The above would provide an exception from `deny_foo` and `deny_bar`.


!!! example
    ```
    package user.kubernetes.ID100

    __rego_metadata := {
        "id": "ID100",
        "title": "Deployment not allowed",
        "severity": "HIGH",
        "type": "Kubernetes Custom Check",
    }
    
    deny_deployment[msg] {
        input.kind == "Deployment"
    	msg = sprintf("Found deployment '%s' but deployments are not allowed", [name])
    }
    
    exception[rules] {
        input.kind == "Deployment"
        input.metadata.name == "allow-deployment"
        
        rules := ["deployment"]
    }
    ```

If you want to apply rule-based exceptions to built-in checks, you have to define the exception under the same package.

!!! example
    ``` rego
    package builtin.kubernetes.KSV012

    exception[rules] {
        input.metadata.name == "can-run-as-root"
        rules := [""]
    }
    ```

This exception is applied to [KSV012][ksv012] in trivy-checks.
You can get the package names in the [trivy-checks repository][trivy-checks] or the JSON output from Trivy.

[ksv012]: https://github.com/aquasecurity/trivy-checks/blob/f36a5b732c4b1293a720c40baab0a7c106ea455e/checks/kubernetes/pss/restricted/3_runs_as_root.rego 
[trivy-checks]: https://github.com/aquasecurity/trivy-checks/