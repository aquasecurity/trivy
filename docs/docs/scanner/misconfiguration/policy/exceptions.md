# Exceptions
Exceptions let you specify cases where you allow policy violations.
Trivy supports two types of exceptions.

!!! info
    Exceptions can be applied to built-in policies as well as custom policies.

## Namespace-based exceptions
There are some cases where you need to disable built-in policies partially or fully.
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

This example exempts all built-in policies for Kubernetes.

For more details, see [an example][ns-example].

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

If you want to apply rule-based exceptions to built-in policies, you have to define the exception under the same package.

!!! example
    ``` rego
    package builtin.kubernetes.KSV012

    exception[rules] {
        input.metadata.name == "can-run-as-root"
        rules := [""]
    }
    ```

This exception is applied to [KSV012][ksv012] in defsec.
You can get the package names in the [defsec repository][defsec] or the JSON output from Trivy.

For more details, see [an example][rule-example].

[ns-example]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/namespace-exception
[rule-example]: https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/rule-exception
[ksv012]: https://github.com/aquasecurity/defsec/blob/master/internal/rules/kubernetes/policies/pss/restricted/3_runs_as_root.rego
[defsec]: https://github.com/aquasecurity/defsec/