# Custom Checks with Rego

Trivy can scan configuration files for common security issues (a.k.a IaC misconfiguration scanning). In addition to a comprehensive built in database of checks, you can add your own custom checks. Checks are written in [Rego](https://www.openpolicyagent.org/docs/latest/policy-language/) language and the full documentation for checks and customizing them is available [here](https://aquasecurity.github.io/trivy/latest/docs/scanner/misconfiguration/custom/). 

This tutorial will walk you through writing a custom check in Rego that checks for an issue in a Dockerfile.

When you are writing a check, it's important to understand the input to the check. This will be the IaC file that you are scanning; for example, a Kubernetes YAML resource definition, or an AWS JSON CloudFormation, or in our case a Dockerfile.

Since Rego is primarily tailored to query JSON objects, all incoming configuration files needs to be first converted to structured objects, which is available to the Rego code as the input variable. This is nothing that users have to do manually in Trivy. Instead, Rego makes it possible to pass in custom Schemas that detail how files are converted. Once Rego has access to a custom Schema, it will know in which format to access configuration files such as a Dockerfile. 

[Here you can find the schemas](https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas) that define how different configuration files are converted to JSON by Trivy.
This tutorial will make use of the [dockerfile.json schema](https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas). The schema will need to be parsed into your custom check. 

Users can also use the [Schema Explorer](https://aquasecurity.github.io/trivy-schemas/) to view the structure of the data provided to Rego.

## Create a Rego file and Specify Trivy metadata

First, create a new `.rego` file e.g. a `docker-check.rego` file:
```
touch docker-check.rego
```

Next, we need to specify metadata about the check. This is information that helps Trivy load and process the check.

```
# METADATA
# title: Verify Image
# description: Verify Image is allowed to be used and in the right format
# schemas:
#   - input: schema["dockerfile"]
# custom:
#   id: ID001
#   severity: MEDIUM
#   input:
#     selector: 
#     - type: dockerfile
```

Important: The `METADATA` has to be defined on top of the file.

More information on the different fields in the metadata can be found in the [Trivy documentation.](https://aquasecurity.github.io/trivy/latest/docs/scanner/misconfiguration/custom/)

## Package and imports

```
package custom.dockerfile.ID001

import future.keywords.in
```

Every rego check has a package name. In our case, we will call it `custom.dockerfile.ID001` to avoid confusion between custom checks and built-in checks. The group name `dockerfile` has no effect on the package name. Note that each package has to contain only one check. However, we can pass multiple checks into our Trivy scan. 
The first keyword of the package, in this case `custom`, will be reused in the `trivy` command as the `--namespace`.

## Allowed data

The check that we are setting up compares the container images used in the Dockerfile with a list of white-listed container images. Thus, we need to add the images that are allowed to be used in the Dockerfile to our check. In our case, we will store them in an array of arrays:

```
allowed_images :=  {
    ["node:21-alpine3.19", "as", "build-deps"],
    ["nginx:1.2"]
}
```

## Select the images that are used in the Dockerfile

Next, we need to iterate over the different commands in our Dockerfile and identify the commands that provide the base container images:

```
deny[msg] {
    input.Stages[m].Commands[l].Cmd == "from"
    val := input.Stages[m].Commands[l].Value
    not val in allowed_images
    msg := sprintf("The container image '%s' used in the Dockerfile is not allowed", val)
}
```

Let's look at the check line by line:

1. The rule should always be `deny` in the Trivy Rego checks
2. `input.Stages[m].Commands[l].Cmd` `input` allows us to access the different commands in the Dockerfile. We need to access the commands that use "FROM". Every command will be converted to lowercase.
3. `val := input.Stages[m].Commands[l].Value` accesses the value of the `FROM` command and stores it in `val`
4. `not val in allowed_images` checks whether val is not part of our allowed images list; this part of the check relies on the import statement
5. In case our check fails, the `msg` will be printed with the image name used in `val` 

Note that Rego

* uses `AND` automatically to combine conditions in this check
* automatically iterates through the array of commands in the Dockefile and allowed images 

## Run the check in a Trivy misconfiguration scan

Ensure that you have Trivy installed and run the following command:

```bash
trivy fs --scanners misconf --policy ./docker-check.rego --namespaces custom ./Dockerfile
```

Please replace:

* `./docker-check.rego` with the file path to your check
* `custom` should be replaced with your package name if different
* `./Dockerfile` is the path to the Dockerfile that should be scanned

**Note**:  If you define custom packages, you have to specify the package prefix via `--namespaces` option. In our case, we called the custom package `custom`.

## Resources

* [Rego provides a long list of courses](https://academy.styra.com/collections) that can be useful in writing more complex checks
* [The Rego documentation provides detailed information on the different types, iterations etc.](https://www.openpolicyagent.org/docs/latest/)
* Have a look at the [built-in checks](https://github.com/aquasecurity/trivy-policies/tree/main/checks) for Trivy for inspiration on how to write custom checks.