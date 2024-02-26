# Add Provider Support

A provider refers to a cloud provier such as AWS or resource type such as Docker.

Before adding a new provider, check whether the provider you would like to add does not already exist in the [trivy repository](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers). Next, create a [discussion](https://github.com/aquasecurity/trivy/discussions/categories/ideas) in the Trivy repository to get input on your plan of adding a new provider.

We highly welcome new contributions!

## Adding a new Provider

First, add a new subdirectory to the [pkg/iac/providers](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) directory in the Trivy repository, named after your provider. Inside this, create a Go file with the same name as your provider and create a Go struct to hold information about all of the services supported by your provider.

For example, adding support for a new provider called foo would look like this:

pkg/iac/providers/foo/foo.go:

```
package foo

type Foo struct {
	// Add services here later...
}
```

Next, you should add a reference to your provider struct in [pkg/state/state.go](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/state/state.go):

```
type State struct {
	// ...
    Foo foo.Foo
	// ...
}
```

Once done, add one or more adapters to [internal/adapters](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/adapters). An adapter takes an input and populates your provider struct. For example, if you want to scan a Terraform plan, you will need to add an adapter that takes the Terraform plan and populates your provider struct. The AWS provider support in Trivy uses multiple adapters - it can adapt CloudFormation, Terraform, and live AWS accounts. Each of these has an adapter in this directory.

To support Terraform as an input, your adapter should look similar to the following:

```
func Adapt(modules terraform.Modules) (foo.Foo, error) {
    return foo.Foo{
		// ...
    }, nil
}
```

Additionally, it needs to be called in [iac/adapters/terraform/adapt.go](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/adapters/terraform/adapt.go) in the case of Terraform.

We recommend browsing the existing adapters to see how they work, as there is a lot of common code that can be reused.