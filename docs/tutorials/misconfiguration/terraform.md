# Scanning Terraform files with Trivy

This tutorial is focused on ways Trivy can scan Terraform IaC configuration files. 

A video tutorial on Terraform Misconfiguration scans can be found on the [Aqua Open Source YouTube account.](https://youtu.be/BWp5JLXkbBc)

**A note to tfsec users** 
We have been consolidating all of our scanning-related efforts in one place, and that is Trivy. You can read more on the decision in the [tfsec discussions.](https://github.com/aquasecurity/tfsec/discussions/1994)

## Trivy Config Command 

Terraform configuration scanning is available as part of the `trivy config` command. This command scans all configuration files for misconfiguration issues. You can find the details within [misconfiguration scans in the Trivy documentation.](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/scanning/) 

Command structure: 
``` 
trivy config <any flags you want to use> <file or directory that you would like to scan> 
``` 

The `trivy config` command can scan Terraform configuration, CloudFormation, Dockerfile, Kubernetes manifests, and Helm Charts for misconfiguration. Trivy will compare the configuration found in the file with a set of best practices.  

- If the configuration is following best practices, the check will pass,  
- If the configuration does not define the resource of some configuration, Trivy will assume the default configuration for the resource creation is used. In this case, the check might fail.
- If the configuration that has been defined does not follow best practices, the check will fail.  

### Prerequisites 
Install Trivy on your local machines. The documentation provides several [different installation options.](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) 
This tutorial will use this example [Terraform tutorial](https://github.com/Cloud-Native-Security/trivy-demo/tree/main/bad_iac/terraform) for terraform misconfiguration scanning with Trivy. 

Git clone the tutorial and cd into the directory: 
``` 
git clone git@github.com:Cloud-Native-Security/trivy-demo.git
cd bad_iac/terraform
``` 
In this case, the folder only containes Terraform configuration files. However, you could scan a directory that contains several different configurations e.g. Kubernetes YAML manifests, Dockerfile, and Terraform. Trivy will then detect the different configuration files and apply the right rules automatically. 

## Different types of `trivy config` scans 

Below are several examples of how the trivy config scan can be used. 

General Terraform scan with trivy: 
``` 
trivy config <specify the directory> 
``` 

So if we are already in the directory that we want to scan: 
``` 
trivy config ./ 
``` 
### Specify the scan format 
The `--format` flag changes the way that Trivy displays the scan result: 

JSON: 
```
trivy config -f json terraform-infra 
``` 

Sarif: 
``` 
trivy config -f sarif terraform-infra 
``` 

### Specifying the output location 

The `--output` flag specifies the file location in which the scan result should be saved: 

JSON: 
``` 
trivy config -f json -o example.json terraform-infra 
``` 

Sarif: 
``` 
trivy config -f sarif -o example.sarif terraform-infra 
``` 

### Filtering by severity 

If you are presented with lots and lots of misconfiguration across different files, you might want to filter or the misconfiguration with the highest severity: 

``` 
trivy config --severity CRITICAL, MEDIUM terraform-infra 
``` 

### Passing tf.tfvars files into `trivy config` scans 

You can pass terraform values to Trivy to override default values found in the Terraform HCL code. More information are provided [in the documentation.](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/options/values/) 

``` 
trivy conf --tf-vars terraform.tfvars ./
``` 
### Custom Checks 

We have lots of examples in the [documentation](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/custom/) on how you can write and pass custom Rego policies into terraform misconfiguration scans. 

## Secret and vulnerability scans

The `trivy config` command does not perform secrete and vulnerability checks out of the box. However, you can specify as part of your `trivy fs` scan that you would like to scan you terraform files for exposed secrets and misconfiguraction through the following flags: 

```
trivy fs --scanners secret,config ./
```

The `trivy config` command is a sub-command of the `trivy fs` command. You can learn more about this command in the [documentation.](https://aquasecurity.github.io/trivy/latest/docs/target/filesystem/) 

## Scanning Terraform Plan files

Instead of scanning your different Terraform resources individually, you could also scan your terraform plan output before it is deployed for misconfiguration. This will give you insights into any misconfiguration of your resources as they would become deployed. [Here](https://aquasecurity.github.io/trivy/latest/docs/scanner/misconfiguration/custom/examples/#terraform-plan) is the link to the documentation.

First, create a terraform plan and save it to a file:
```
terraform plan --out tfplan.binary
```

Next, convert the file into json format:
```
terraform show -json tfplan.binary > tfplan.json
```

Lastly, scan the file with the `trivy config` command:
```
trivy config ./tfplan.json
```

Note that you need to be able to create a terraform init and plan without any errors. 

## Using Trivy in your CI/CD pipeline 
Similar to tfsec, Trivy can be used either on local developer machines or integrated into your CI/CD pipeline. There are several steps available for different pipelines, including GitHub Actions, Circle CI, GitLab, Travis and more in the tutorials section of the documentation: [https://aquasecurity.github.io/trivy/latest/tutorials/integrations/](https://aquasecurity.github.io/trivy/latest/tutorials/integrations/) 

 