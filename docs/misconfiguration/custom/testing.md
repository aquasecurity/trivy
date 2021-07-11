# Testing
It is highly recommended to write tests for your custom policies.

## Rego testing
To help you verify the correctness of your custom policies, OPA gives you a framework that you can use to write tests for your policies. 
By writing tests for your custom policies you can speed up the development process of new rules and reduce the amount of time it takes to modify rules as requirements evolve.

For more details, see [Policy Testing][opa-testing].

!!! example
    ```
    package user.dockerfile.ID002

    test_add_denied {
        r := deny with input as {"stages": {"alpine:3.13": [
            {"Cmd": "add", "Value": ["/target/resources.tar.gz", "resources.jar"]},
            {"Cmd": "add", "Value": ["/target/app.jar", "app.jar"]},
        ]}}

        count(r) == 1
        r[_] == "Consider using 'COPY /target/app.jar app.jar' command instead of 'ADD /target/app.jar app.jar'"
    }
    ```

To write tests for custom policies, you can refer to existing tests under [AppShield][appshield].

## Go testing
[Fanal][fanal] which is a core library of Trivy can be imported as a Go library.
You can scan config files in Go and test your custom policies using Go's testing methods, such as [table-driven tests][table].
This allows you to use the actual configuration file as input, making it easy to prepare test data and ensure that your custom policies work in practice.

In particular, Dockerfile and HCL need to be converted to structural data as input, which may be different from the expected input format.

!!! tip
    We recommend writing OPA and Go tests both since they have different roles, like unit tests and integration tests.

The following example stores allowed and denied configuration files in a directory.
`Successes` contains the result of successes, and `Failures` contains the result of failures.

``` go
{
	name:  "disallowed ports",
	input: "configs/",
	fields: fields{
		policyPaths: []string{"policy"},
		dataPaths:   []string{"data"},
		namespaces:  []string{"user"},
	},
	want: []types.Misconfiguration{
		{
			FileType: types.Dockerfile,
			FilePath: "Dockerfile.allowed",
			Successes: types.MisconfResults{
				{
					Namespace: "user.dockerfile.ID002",
					PolicyMetadata: types.PolicyMetadata{
						ID:          "ID002",
						Type:        "Docker Custom Check",
						Title:       "Disallowed ports exposed",
						Severity:    "HIGH",
					},
				},
			},
		},
		{
			FileType: types.Dockerfile,
			FilePath: "Dockerfile.denied",
			Failures: types.MisconfResults{
				{
					Namespace: "user.dockerfile.ID002",
					Message:   "Port 23 should not be exposed",
					PolicyMetadata: types.PolicyMetadata{
						ID:          "ID002",
						Type:        "Docker Custom Check",
						Title:       "Disallowed ports exposed",
						Severity:    "HIGH",
					},
				},
			},
		},
	},
},
```

`Dockerfile.allowed` has one successful result in `Successes`, while `Dockerfile.denied` has one failure result in `Failures`.

[opa-testing]: https://www.openpolicyagent.org/docs/latest/policy-testing/
[appshield]: https://github.com/aquasecurity/appshield
[table]: https://github.com/golang/go/wiki/TableDrivenTests
[fanal]: https://github.com/aquasecurity/fanal