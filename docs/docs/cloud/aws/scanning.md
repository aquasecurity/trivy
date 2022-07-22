# Amazon Web Services

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

The Trivy AWS CLI allows you to scan your AWS account for misconfigurations. You can either run the CLI locally or integrate it into your CI/CD pipeline. 

Whilst you can already scan the infrastructure-as-code that defines your AWS resources with `trivy config`, you can now scan your live AWS account(s) directly too.

Trivy uses your [local AWS configuration](Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) to configure and authenticate your access to the AWS platform.

Once you've scanned your account, you can run additional commands to filter the results without having to run the entire scan again - results are cached locally per AWS account/region.

## CLI Commands

Scan a full AWS account (all supported services):

```
$ trivy aws --region us-east-1
```

You can allow Trivy to determine the AWS region etc. by using the standard AWS configuration files and environment variables. The `--region` flag overrides these.

![AWS Summary Report](../../../imgs/trivy-aws.png)

The summary view is the default when scanning multiple services.

Scan a specific service:

```
$ trivy aws --service s3
```

Scan multiple services:

```
$ trivy aws --service s3 --service ec2
```

Show results for a specific AWS resource:

```
$ trivy aws --service s3 --arn arn:aws:s3:::example-bucket
```

All ARNs with detected issues will be displayed when showing results for their associated service.
