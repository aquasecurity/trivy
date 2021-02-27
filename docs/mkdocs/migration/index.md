On 19 August 2019, Trivy's repositories moved from `knqyf263/trivy` to `aquasecurity/trivy`. If you previously installed Trivy you should update any scripts or package manager records as described in this section.

If you have a script that installs Trivy (for example into your CI pipelines) you should update it to obtain it from the new location by replacing knqyf263/trivy with aquasecurity/trivy.

For example:
```bash
# Before
$ wget https://github.com/knqyf263/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz

# After
$ wget https://github.com/aquasecurity/trivy/releases/download/v${VERSION}/trivy_${VERSION}_Linux-64bit.tar.gz
```
