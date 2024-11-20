# Installing Trivy

In this section you will find an aggregation of the different ways to install Trivy. Installation options are labeled as either "Official" or "Community". Official installations are developed by the Trivy team and supported by it. Community installations could be developed by anyone from the Trivy community, and collected here for your convenience. For support or questions about community installations, please contact the original developers.

!!! note
    If you are looking to integrate Trivy into another system, such as CI/CD, IDE, Kubernetes, etc, please see [Ecosystem section](../ecosystem/index.md) to explore integrations of Trivy with other tools.

## Container image (Official)

Use one of the official Trivy images:

| Registry | Repository | Link |
| --- | --- | --- |
| Docker Hub | `docker.io/aquasec/trivy` | https://hub.docker.com/r/aquasec/trivy |
| GitHub Container Registry (GHCR) | `ghcr.io/aquasecurity/trivy` | https://github.com/orgs/aquasecurity/packages/container/package/trivy |
| AWS Elastic Container Registry (ECR) | `public.ecr.aws/aquasecurity/trivy` | https://gallery.ecr.aws/aquasecurity/trivy |

!!! Tip
    It is advisable to mount a persistent [cache dir](../docs/configuration/cache.md) on the host into the Trivy container.

!!! Tip
    For scanning container images with Trivy, mount the container engine socket from the host into the Trivy container.

Example:

``` bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy:{{ git.tag[1:] }} image python:3.4-alpine
```

## GitHub Release (Official)

1. Download the file for your operating system/architecture from [GitHub Release assets](https://github.com/aquasecurity/trivy/releases/tag/{{ git.tag }}).  
2. Unpack the downloaded archive (`tar -xzf ./trivy.tar.gz`).
3. Make sure the binary has execution bit turned on (`chmod +x ./trivy`).

## Install Script (Official)

For convenience, you can use the install script to download and install Trivy from GitHub Release.

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin {{ git.tag }}
```

## RHEL/CentOS (Official)

=== "Repository"
    Add repository setting to `/etc/yum.repos.d`.

    ``` bash
    cat << EOF | sudo tee -a /etc/yum.repos.d/trivy.repo
    [trivy]
    name=Trivy repository
    baseurl=https://aquasecurity.github.io/trivy-repo/rpm/releases/\$basearch/
    gpgcheck=1
    enabled=1
    gpgkey=https://aquasecurity.github.io/trivy-repo/rpm/public.key
    EOF
    sudo yum -y update
    sudo yum -y install trivy
    ```

=== "RPM"

    ``` bash
    rpm -ivh https://github.com/aquasecurity/trivy/releases/download/{{ git.tag }}/trivy_{{ git.tag[1:] }}_Linux-64bit.rpm
    ```

## Debian/Ubuntu (Official)

=== "Repository"
    Add repository setting to `/etc/apt/sources.list.d`.

    ``` bash
    sudo apt-get install wget gnupg
    wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
    sudo apt-get update
    sudo apt-get install trivy
    ```

=== "DEB"

    ``` bash
    wget https://github.com/aquasecurity/trivy/releases/download/{{ git.tag }}/trivy_{{ git.tag[1:] }}_Linux-64bit.deb
    sudo dpkg -i trivy_{{ git.tag[1:] }}_Linux-64bit.deb
    ```

## Homebrew (Official)

Homebrew for macOS and Linux.

```bash
brew install trivy
```

## Windows (Official)

1. Download trivy_x.xx.x_windows-64bit.zip file from [releases page](https://github.com/aquasecurity/trivy/releases/).
2. Unzip file and copy to any folder.

## Arch Linux (Community)

Arch Linux Package Repository.

```bash
sudo pacman -S trivy
```

References: 
- <https://archlinux.org/packages/extra/x86_64/trivy/>
- <https://gitlab.archlinux.org/archlinux/packaging/packages/trivy/-/blob/main/PKGBUILD>


## MacPorts (Community)

[MacPorts](https://www.macports.org) for macOS.

```bash
sudo port install trivy
```

References:
- <https://ports.macports.org/port/trivy/details/>

## Nix/NixOS (Community)

Nix package manager for Linux and macOS.

=== "Command line"
    `nix-env --install -A nixpkgs.trivy`

=== "Configuration"
    ```nix
    # your other config ...
    environment.systemPackages = with pkgs; [
      # your other packages ...
      trivy
    ];
    ```

=== "Home Manager"
    ```nix
    # your other config ...
    home.packages = with pkgs; [
      # your other packages ...
      trivy
    ];
    ```

References: 

-  https://github.com/NixOS/nixpkgs/blob/master/pkgs/tools/admin/trivy/default.nix

## FreeBSD (Official)

Pkg package manager for FreeBSD.

```bash
pkg install trivy
```

## asdf/mise (Community)

[asdf](https://github.com/asdf-vm/asdf) and [mise](https://github.com/jdx/mise) are quite similar tools you can use to install trivy.
See their respective documentation for more information of how to install them and use them:

- [asdf](https://asdf-vm.com/guide/getting-started.html)
- [mise](https://mise.jdx.dev/getting-started.html)

The plugin used by both tools is developped [here](https://github.com/zufardhiyaulhaq/asdf-trivy)


=== "asdf"
    A basic global installation is shown below, for specific version or/and local version to a directory see "asdf" documentation.

    ```shell
    # Install plugin
    asdf plugin add trivy https://github.com/zufardhiyaulhaq/asdf-trivy.git

    # Install latest version
    asdf install trivy latest

    # Set a version globally (on your ~/.tool-versions file)
    asdf global trivy latest

    # Now trivy commands are available
    trivy --version
    ```

=== "mise"
    A basic global installation is shown below, for specific version or/and local version to a directory see "mise" documentation.

    ``` shell
    # Install plugin and install latest version
    mise install trivy@latest

    # Set a version globally (on your ~/.tool-versions file)
    mise use -g trivy@latest

    # Now trivy commands are available
    trivy --version
    ```
