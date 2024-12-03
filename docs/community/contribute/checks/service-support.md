# Add Service Support

A service refers to a service by a cloud provider. This section details how to add a new service to an existing provider. All contributions need to be made to the [trivy repository](https://github.com/aquasecurity/trivy/).

## Prerequisites

Before you begin, verify that the [provider](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) does not already have the service that you plan to add.

## Adding a new service to an existing provider

Adding a new service involves two steps. The service will need a data structure to store information about the required resources that will be scanned. Additionally, the service will require one or more adapters to convert the scan targetes as input(s) into the aforementioned data structure.

### Create a new file in the provider directory

In this example, we are adding the CodeBuild service to the AWS provider.

First, create a new directory and file for your new service under the provider directory: e.g. [aws/codebuild/codebuild.go](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/providers/aws/codebuild/codebuild.go)

The CodeBuild service will require a structure `struct` to hold the information on the input that is scanned. The input is the CodeBuild resource that a user configured and wants to scan for misconfiguration.

```
type CodeBuild struct {
	Projects []Project
}
```

The CodeBuild service manages `Project` resources. The `Project` struct has been added to hold information about each Project resources; `Project` Resources in turn manage `ArtifactSettings`:

```
type Project struct {
	Metadata                  iacTypes.Metadata
	ArtifactSettings          ArtifactSettings
	SecondaryArtifactSettings []ArtifactSettings
}

type ArtifactSettings struct {
	Metadata          iacTypes.Metadata
	EncryptionEnabled iacTypes.BoolValue
}
```

The `iacTypes.Metadata` struct is embedded in all of the Trivy types and provides a common set of metadata for all resources. This includes the file and line number where the resource was defined and the name of the resource.

A resource in this example `Project` can have a name and can optionally be encrypted. Instead of using raw string and bool types respectively, we use the trivy types `iacTypes.Metadata` and `iacTypes.BoolValue`. These types wrap the raw values and provide additional metadata about the value. For instance, whether it was set by the user and the file and line number where the resource was defined. 

Have a look at the other providers and services in the [`iac/providers`](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/providers) directory in Trivy.

Next you'll need to add a reference to your new service struct in the [provider struct](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/providers/aws/aws.go) at `pkg/iac/providers/aws/aws.go`:

```
type AWS struct {
	...
	CodeBuild      codebuild.CodeBuild
    ...
}
```

### Update Adapters

Now you'll need to update all of the [adapters](https://github.com/aquasecurity/trivy/tree/main/pkg/iac/adapters) which populate the struct of the provider that you have been using. Following the example above, if you want to add support for CodeBuild in Terraform, you'll need to update the Terraform AWS adatper as shown here: [`trivy/pkg/iac/adapters/terraform/aws/codebuild/adapt.go`](https://github.com/aquasecurity/trivy/blob/main/pkg/iac/adapters/terraform/aws/codebuild/adapt.go).

Another example for updating the adapters is provided in the [following PR.](https://github.com/aquasecurity/defsec/pull/1000/files) Additionally, please refer to the respective Terraform documentation on the provider to which you are adding the service. For instance, the Terraform documentation for AWS CodeBuild is provided [here.](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project)


## Create a new Schema for your provider

Once the new service has been added to the provider, you need to create the schema for the service as part of the provider schema. 

This process has been automated with mage commands. In the Trivy root directory run `mage schema:generate` to generate the schema for your new service and `mage schema:verify`.
