# Exceptions
Trivy supports two types of exceptions.

!!! info
    Exceptions can be applied to built-in policies as well as custom policies.

## Rule-based exceptions
There might be cases where rules might not apply under certain circumstances.
For those occasions, you can use rule-based exceptions. 
Rule-based exceptions are also written in Rego, and allow you to specify policies for when a given `deny` rule does not apply.

Inputs matched by the exception will be exempted from the rules specified in rules, prefixed by `deny_`:

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
    package appshield.kubernetes.KSV012

    exception[rules] {
        input.metadata.name == "can-run-as-root"
        rules := [""]
    }
    ```

This exception is applied to [KSV012](https://github.com/aquasecurity/appshield/blob/57bccc1897b2500a731415bda3990b0d4fbc959e/kubernetes/policies/pss/restricted/3_runs_as_root.rego) in AppShield.
You can get the package names in [AppShield repository](https://github.com/aquasecurity/appshield/) or the JSON output from Trivy.

For more details, see [the example](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/rule-exception)

## Namespace-based exceptions
You might want to disable built-in policies partially or fully.
For those occasions, you can use namespace-based exceptions.
Namespace-based exceptions are also written in Rego, and allow you to specify packages where you want to disable.

The package name must be `namespace.exceptions`.
Packages returned by `exception` will be exempted.
`data.namespaces` includes all package names.


!!! example
    ``` rego
        package namespace.exceptions
        
        import data.namespaces
        
        exception[ns] {
            ns := data.namespaces[_]
            startswith(ns, "appshield")
        }
    ```

This example exempts all built-in policies for Kubernetes.

For more details, see [the example](https://github.com/aquasecurity/trivy/tree/{{ git.commit }}/examples/misconf/namespace-exception)
