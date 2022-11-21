# CLI Installation

## RHEL/CentOS

=== "Repository"
    Add repository setting to `/etc/yum.repos.d`.

    ``` bash
    RELEASE_VERSION=$(grep -Po '(?<=VERSION_ID=")[0-9]' /etc/os-release)
    cat << EOF | sudo tee -a /etc/yum.repos.d/trivy.repo
    [trivy]
    name=Trivy repository
    baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/$RELEASE_VERSION/\$basearch/
    gpgcheck=0
    enabled=1
    EOF
    sudo yum -y update
    sudo yum -y install trivy
    ```

=== "RPM"

    ``` bash
    rpm -ivh https://github.com/aquasecurity/trivy/releases/download/{{ git.tag }}/trivy_{{ git.tag[1:] }}_Linux-64bit.rpm
    ```

## Debian/Ubuntu

=== "Repository"
    Add repository setting to `/etc/apt/sources.list.d`.

    ``` bash
    sudo apt-get install wget apt-transport-https gnupg lsb-release
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install trivy
    ```

=== "DEB"

    ``` bash
    wget https://github.com/aquasecurity/trivy/releases/download/{{ git.tag }}/trivy_{{ git.tag[1:] }}_Linux-64bit.deb
    sudo dpkg -i trivy_{{ git.tag[1:] }}_Linux-64bit.deb
    ```

## Arch Linux

Package trivy can be installed from the Arch Community Package Manager.

```bash
pacman -S trivy
```

## Homebrew

You can use homebrew on macOS and Linux.

```bash
brew install aquasecurity/trivy/trivy
```

## MacPorts

You can also install `trivy` via [MacPorts](https://www.macports.org) on macOS:

```bash
sudo port install trivy
```

More info [here](https://ports.macports.org/port/trivy/).

## Nix/NixOS

Direct issues installing `trivy` via `nix` through the channels mentioned [here](https://nixos.wiki/wiki/Support)

You can use `nix` on Linux or macOS and on other platforms unofficially.

`nix-env --install -A nixpkgs.trivy`

Or through your configuration as usual

NixOS:

```nix
  # your other config ...
  environment.systemPackages = with pkgs; [
    # your other packages ...
    trivy
  ];
```

home-manager:

```nix
  # your other config ...
  home.packages = with pkgs; [
    # your other packages ...
    trivy
  ];
```

## Install Script

This script downloads Trivy binary based on your OS and architecture.

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin {{ git.tag }}
```

## Binary

Download the archive file for your operating system/architecture from [here](https://github.com/aquasecurity/trivy/releases/tag/{{ git.tag }}).
Unpack the archive, and put the binary somewhere in your `$PATH` (on UNIX-y systems, /usr/local/bin or the like).
Make sure it has execution bits turned on.

## From source

```bash
mkdir -p $GOPATH/src/github.com/aquasecurity
cd $GOPATH/src/github.com/aquasecurity
git clone --depth 1 --branch {{ git.tag }} https://github.com/aquasecurity/trivy
cd trivy/cmd/trivy/
export GO111MODULE=on
go install
```

## Docker

### Docker Hub

Replace [YOUR_CACHE_DIR] with the cache directory on your machine.

```bash
docker pull aquasec/trivy:{{ git.tag[1:] }}
```

Example:

=== "Linux"

    ``` bash
    docker run --rm -v [YOUR_CACHE_DIR]:/root/.cache/ aquasec/trivy:{{ git.tag[1:] }} image [YOUR_IMAGE_NAME]
    ```

=== "macOS"

    ``` bash
    docker run --rm -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy:{{ git.tag[1:] }} image [YOUR_IMAGE_NAME]
    ```

If you would like to scan the image on your host machine, you need to mount `docker.sock`.

```bash
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy:{{ git.tag[1:] }} image python:3.4-alpine
```

Please re-pull latest `aquasec/trivy` if an error occurred.

<details>
<summary>Result</summary>

```bash
2019-05-16T01:20:43.180+0900    INFO    Updating vulnerability database...
2019-05-16T01:20:53.029+0900    INFO    Detecting Alpine vulnerabilities...

python:3.4-alpine3.9 (alpine 3.9.2)
===================================
Total: 1 (UNKNOWN: 0, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 0)

+---------+------------------+----------+-------------------+---------------+--------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |             TITLE              |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
| openssl | CVE-2019-1543    | MEDIUM   | 1.1.1a-r1         | 1.1.1b-r1     | openssl: ChaCha20-Poly1305     |
|         |                  |          |                   |               | with long nonces               |
+---------+------------------+----------+-------------------+---------------+--------------------------------+
```

</details>

### GitHub Container Registry

The same image is hosted on [GitHub Container Registry][registry] as well.

```bash
docker pull ghcr.io/aquasecurity/trivy:{{ git.tag[1:] }}
```

### Amazon ECR Public

The same image is hosted on [Amazon ECR Public][ecr] as well.

```bash
docker pull public.ecr.aws/aquasecurity/trivy:{{ git.tag[1:] }}
```

### AWS private registry permissions

You may need to grant permissions to allow trivy to pull images from private registry (AWS ECR).

It depends on how you want to provide AWS Role to trivy.

- [IAM Role Service account](https://github.com/aws/amazon-eks-pod-identity-webhook)
- [Kube2iam](https://github.com/jtblin/kube2iam) or [Kiam](https://github.com/uswitch/kiam)

#### IAM Role Service account

Add the AWS role in trivy's service account annotations:

```yaml
trivy:

  serviceAccount:
    annotations: {}
      # eks.amazonaws.com/role-arn: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
```

#### Kube2iam or Kiam

Add the AWS role to pod's annotations:

```yaml
podAnnotations: {}
  ## kube2iam/kiam annotation
  # iam.amazonaws.com/role: arn:aws:iam::ACCOUNT_ID:role/IAM_ROLE_NAME
```

> **Tip**: List all releases using `helm list`.

## Other Tools to use and deploy Trivy

For additional tools and ways to install and use Trivy in different environments such as in Docker Desktop and Kubernetes clusters, see the links in the [Ecosystem section](../ecosystem/index.md).


[ecr]: https://gallery.ecr.aws/aquasecurity/trivy
[registry]: https://github.com/orgs/aquasecurity/packages/container/package/trivy
[helm]: https://github.com/aquasecurity/trivy/tree/{{ git.tag }}/helm/trivy
[slack]: https://slack.aquasec.com
[operator-docs]: https://aquasecurity.github.io/trivy-operator/latest/

[vuln]: ./docs/vulnerability/scanning/index.md
[misconf]: ./docs/misconfiguration/scanning.md
[kubernetesoperator]: ./docs/kubernetes/operator/index.md
[container]: ./docs/vulnerability/scanning/image.md
[rootfs]: ./docs/vulnerability/scanning/rootfs.md
[filesystem]: ./docs/vulnerability/scanning/filesystem.md
[repo]: ./docs/vulnerability/scanning/git-repository.md
[kubernetes]: ./docs/kubernetes/cli/scanning.md

[standalone]: ./docs/references/modes/standalone.md
[client-server]: ./docs/references/modes/client-server.md
[integrations]: ./tutorials/integrations/index.md

[os]: ./docs/vulnerability/detection/os.md
[lang]: ./docs/vulnerability/detection/language.md
[builtin]: ./docs/misconfiguration/policy/builtin.md
[quickstart]: ./getting-started/quickstart.md
[podman]: ./docs/advanced/container/podman.md

[sbom]: ./docs/sbom/index.md

[oci]: https://github.com/opencontainers/image-spec
[license]:  https://github.com/aquasecurity/trivy/blob/main/LICENSE
