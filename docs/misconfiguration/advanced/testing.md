# Testing
It is highly recommended to write tests after creating custom policies.

## Rego testing
To help you verify the correctness of your custom policies, OPA gives you a framework that you can use to write tests for your policies. 
By writing tests for your custom policies you can speed up the development process of new rules and reduce the amount of time it takes to modify rules as requirements evolve.

For more details, see [Policy Testing](https://www.openpolicyagent.org/docs/latest/policy-testing/).

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

To write tests for custom policies, you can refer to tests under [AppShield](https://github.com/aquasecurity/appshield).