# Add Service Support

A service refers to a service by a cloud provider. This section details how to add a new service to an existing provider. All contributions need to be made to the [defsec repository](https://github.com/aquasecurity/defsec/).

Before you begin, verify that the provider does not already have the service that you plan to add.

Adding a new service involves two steps. The service will need a data structure to store information about the required resources, and then one or more adapters to convert input(s) into the aforementioned data structure.

## Adding a new service to an existing provider

To add a new service named `Bar` to a provider named `foo`, you'll need to add a new file at `pkg/providers/foo/bar/bar.go`:

```
type Bar struct {
    // ...
}
```

Let's say the `Bar` service manages resources called `Baz`. You'll need to add a new struct to the `Bar` struct to hold information about this resource:

```
type Bar struct {
    // ...
    Baz []Baz
    // ...
}

type Baz struct {
    types.Metadata
	Name types.StringValue
	Encrypted types.BoolValue
}
```

A `Baz` can have a name, and can optionally be encrypted. Instead of using raw string and bool types respectively, we use the defsec types `types.StringValue` and `types.BoolValue`. These types wrap the raw values and provide additional metadata about the value, such as whether it was set by the user or not, and the file and line number where the resource was defined. The `types.Metadata` struct is embedded in all of the defsec types, and provides a common set of metadata for all resources. This includes the file and line number where the resource was defined, and the name of the resource.

Next you'll need to add a reference to your new service struct in the provider struct at `pkg/providers/foo/foo.go`:

```
type Foo struct {
    // ...
    Bar bar.Bar
    // ...
}
```

Now you'll need to update all of the adapters which populate the Foo provider struct. For example, if you want to support Terraform, you'll need to update `internal/adapters/terraform/foo/bar/adapt.go`.

Finally, make sure you run make schema to generate the schema for your new service.