# Custom Policies with Rego

This tutorial uses the Trivy [custom policies documentation](https://aquasecurity.github.io/trivy/v0.49/docs/scanner/misconfiguration/custom) to showcase how to write a custom policy for a Dockerfile.

The Schemas that Trivy imports for misconfiguration scanning can be found here: https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas

This tutorial will make use of the [dockerfile.json schema](https://github.com/aquasecurity/defsec/tree/master/pkg/rego/schemas). Alternatively, users can use the [Schema Explorer.](https://aquasecurity.github.io/trivy-schemas/)
Either schema listed in the directory is needed to verify our configuration file. 

## Specify Trivy metadata

First, we need to specify metadata for Trivy:
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

Here are the important parts of the metadata:

* It is a `dockerfile` schema that we will be using. Alternatively, you can pass in custom schemas as shown in this [tutorial.](https://github.com/Cloud-Native-Security/gitops-the-magickey)
* `custom.input.selector` this references the custom input type that will be used in the policy. You can find a list in the [following section.](https://github.com/aquasecurity/defsec/blob/418759b4dc97af25f30f32e0bd365be7984003a1/pkg/types/sources.go)
* `custom.id` you can give the policy any id that you like but make sure it does not clash/is not the same as other IDs is the default Trivy scans.
* `custom.severity` specify the severity of the policy

## Package and imports

```
package user.dockerfile.ID001

import future.keywords.in
```

Every rego policy has a package name. In our case, we will call it `user.dockerfile.ID001`. The group name `dockerfile` has no effect on the package name. Note that each package has to contain only one policy. However, we can pass multiple policies into our Trivy scan. 
The first keyword of the package, in this case `user`, will be reused in the `trivy` command as the `--namespace`.


## Allowed data

Now we need to get the images that are allowed to be used in the Dockerfile and store them in a set of arrays:
```
allowed_images :=  {
    ["node:21-alpine3.19", "as", "build-deps"],
    ["nginx:1.2"]
}
```

## Select the images that are used in the Dockferfile

Next, we need to iterate over the different commands in our Dockerfile and identify the commands that use base container images:
```
deny[msg] {
    some m,l
    input.Stages[m].Commands[l].Cmd == "from"
    val := input.Stages[m].Commands[l].Value
    not val in allowed_images
    msg := sprintf("The container image '%s' used in the Dockerfile is not allowed", val)
}
```

Let's look at the policy line by line:

1. We are using a `deny` policy. More info on the different policies that can be used is provided in the [documentation.](https://aquasecurity.github.io/trivy/v0.49/docs/scanner/misconfiguration/custom/#policy-structure)
2. `some` is used in Rego to iterate over items in an array
3. `input.Stages[m].Commands[l].Cmd` `input` allows us to access the different commands in the Dockerfile. We need to access the commands that use "FROM". Every command will be converted to lowercase.
4. `val := input.Stages[m].Commands[l].Value` accesses the value of the `FROM` command and stores it in `val`
5. `not val in allowed_images` checks whether val is not part of our allowed images list; this part of the policy relies on the import statement
6. In case our policy fails, the `msg` will be printed with the image name used in `val` 

Note that Rego

* uses `AND` automatically to combine conditions in this policy.
* automatically iterates through the array of allowed images 

## Run the policy in a Trivy misconfiguration scan
```bash
trivy config --policy ./image-one.rego --namespaces user ./Dockerfile
```

Please replace:

* `./image-one.rego` with the file path to your policy
* `user` should be replaced with your package name
* `./Dockerfile` is the path to the Dockerfile that should be scanned

**Note**:  If you define custom packages, you have to specify the package prefix via `--namespaces` option. In our case, we called the custom package `user`.

## Resources

* [Rego provides a long list of courses](https://academy.styra.com/collections) that can be useful in writing more complex policies
* [The Rego documentation provides detailed information on the different types, iterations etc.](https://www.openpolicyagent.org/docs/latest/)