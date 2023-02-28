# Trivy Terraform Scan 

This tutorial is focused on ways Trivy can scan Terraform IaC configuration files. 

**A note to tfsec users** 
We have been consolidating all of our scanning-related efforts in one place, and that is Trivy. Over the past year, tfsec has laid the foundations to Trivy's IaC & misconfigurations scanning capabilities, including Terraform scanning, which has been natively supported in Trivy for a long time now. 
Going forward we want to encourage the tfsec community to transition over to Trivy. Moving to Trivy gives you the same excellent Terraform scanning engine, with some extra benefits: 

- Access to more languages and features in the same tool. 
- Access to more integrations with tools and services through the rich ecosystem around Trivy. 
- Commercially supported by Aqua as well as by a the passionate Trivy community. 

Furthermore, Trivy can already check [AWS services for misconfiguration](https://aquasecurity.github.io/trivy/latest/docs/target/aws/). We are currently in the process of merging [Cloudsploit](https://github.com/aquasecurity/cloudsploit) checks into Trivy so that Trivy will be able to perform more checks on cloud provider resources. 

## Trivy Config Command 

Terraform configuration scanning is available as part of the `trivy config` command. This command scans all configuration files for misconfiguration issues.  

Command structure: 
``` 
trivy config <any flags you want to use> <file or directory that you would like to scan> 
``` 

The `trivy config` command can scan Terraform configuration, CloudFormation, Dockerfile, Kubernetes manifests, and Helm Charts for misconfiguration. Trivy will compare the configuration found in the file with a set of best practices.  

- If the configuration is following best practices, the check will pass,  
- If the configuration does not define some configuration according to best practices, the default is used, 
- If the configuration does not follow best practices, the check will fail.  

## Using the `trivy config` command 

The `trivy config` command is used like any other Trivy command. You can find the details within [misconfiguration scans in the Trivy documentation.](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/scanning/) 

### Prerequisites 
Install Trivy on your local machines. The documentation provides several [different installation options.](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) 
This tutorial will use this example [Terraform tutorial]() for terraform misconfiguration scanning with Trivy. 
Git clone the tutorial and cd into the directory: 
``` 
git clone https://github.com/Cloud-Native-Security/terraform-and-argocd 
cd terraform-and-argocd 
``` 
In this case, the folder only containes Terraform configuration files. However, you could scan a directory that contains several different configurations e.g. Kubernetes YAML manifests, Dockerfile, and Terraform. In this case, Trivy detects the different configuration files and applies the right rules automatically. 

## Different types of `trivy config` scans 

Below are several examples of how the trivy config scan can be used. 

General Terraform scan with trivy: 
``` 
trivy config <specify the directory> 
``` 
So if we are already in the directory that we want to scan: 
``` 
trivy config terraform-infra 
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

The `--output` flag specifies the file location in which the scan result should be saved to: 

JSON: 
``` 
trivy config -f json -o example.json terraform-infra 
``` 

Sarif: 
``` 
trivy config -f sarif-o example.sarif terraform-infra 
``` 

### Defining the severity of misconfiguration 

If you are presented with lots and lots of misconfiguration across different files, you might want to filter or the misconfiguration with the highest severity: 

``` 
trivy config --severity CRITICAL, MEDIUM terraform-infra 
``` 

### Passing tf.vars files into `trivy config` scans 

You can pass tf-vars files to Trivy to override default values found in the Terraform HCL code. More information are provided [in the documentation.](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/options/values/) 

``` 
trivy conf --tf-vars dev.terraform.tfvars ./terraform-infra 
``` 
### Custom Policy 

We have lots of example in the [documentation](https://aquasecurity.github.io/trivy/latest/docs/misconfiguration/custom/) on how you can write and pass custom Rego policies into terraform misconfiguration scans. 

## Secret scans and vulnerability scans as part of misconfiguration scans 

The trivy config` command does not perform secrete and vulnerability checks out of the box. However, you can specify as part of your `trivy fs` scan that you would like to scan you terraform files for exposed secrets through an additional flag: 

```
trivy fs --scanners secret ./terraform-infra 
```

The `trivy config` command is a sub-command of the `trivy fs` command. You can learn more about this command in the [documentation.](https://aquasecurity.github.io/trivy/latest/docs/target/filesystem/) 

## Using Trivy in your CI/CD pipeline 
Similar to tfsec, Trivy can be used either on local developer machines or integrated into your CI/CD pipeline. There are several steps available for different pipelines, including GitHub Actions, Circle CI, GitLab, Travis and more in the tutorials section of the documentation: [https://aquasecurity.github.io/trivy/latest/tutorials/integrations/ ](https://aquasecurity.github.io/trivy/latest/tutorials/integrations/) 

 