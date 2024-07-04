# Installing Trivy

In this section you will find an aggregation of the different ways to install Trivy. installations are listed as either "official" or "community". Official integrations are developed by the core Trivy team and supported by it. Community integrations are integrations developed by the community, and collected here for your convenience. For support or questions about community integrations, please contact the original developers.

## Install using Package Manager

### RHEL/CentOS (Official)

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

### Debian/Ubuntu (Official)

=== "Repository"
    Add repository setting to `/etc/apt/sources.list.d`.

    ``` bash
    sudo apt-get install wget apt-transport-https gnupg
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

### Homebrew (Official)

Homebrew for MacOS and Linux.

```bash
brew install trivy
```

### Arch Linux (Community)

Arch Linux Package Repository.

```bash
sudo pacman -S trivy
```

References: 
- <https://archlinux.org/packages/extra/x86_64/trivy/>
- <https://gitlab.archlinux.org/archlinux/packaging/packages/trivy/-/blob/main/PKGBUILD>


### MacPorts (Community)

[MacPorts](https://www.macports.org) for MacOS.

```bash
sudo port install trivy
```

References:
- <https://ports.macports.org/port/trivy/details/>

### Nix/NixOS (Community)

Nix package manager for Linux and MacOS.

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

### FreeBSD (Official)

[Pkg](https://freebsd.org) for FreeBSD.

```bash
pkg install trivy
```

### asdf/mise (Community)

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

## Install from GitHub Release (Official)

### Download Binary

1. Download the file for your operating system/architecture from [GitHub Release assets](https://github.com/aquasecurity/trivy/releases/tag/{{ git.tag }}).  
2. Unpack the downloaded archive (`tar -xzf ./trivy.tar.gz`).
3. Make sure the binary has execution bit turned on (`chmod +x ./trivy`).
4. Put the binary somewhere in your `$PATH` (e.g `sudo mv ./trivy /usr/local/bin/`).

### Install Script

The process above can be automated by the following script:

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin {{ git.tag }}
```

### Install from source

```bash
git clone --depth 1 --branch {{ git.tag }} https://github.com/aquasecurity/trivy
cd trivy
go install ./cmd/trivy
```

## Use container image

1. Pull Trivy image (`docker pull aquasec/trivy:{{ git.tag[1:] }}`)
   2. It is advisable to mount a consistent [cache dir](../docs/configuration/cache.md) on the host into the Trivy container.
3. For scanning container images with Trivy, mount `docker.sock` from the host into the Trivy container.

Example:

``` bash
docker run -v /var/run/docker.sock:/var/run/docker.sock -v $HOME/Library/Caches:/root/.cache/ aquasec/trivy:{{ git.tag[1:] }} image python:3.4-alpine
```

| Registry                             | Repository                          | Link                                                                  | Supportability |
|--------------------------------------|-------------------------------------|-----------------------------------------------------------------------|----------------|
| Docker Hub                           | `docker.io/aquasec/trivy`           | https://hub.docker.com/r/aquasec/trivy                                | Official       |
| GitHub Container Registry (GHCR)     | `ghcr.io/aquasecurity/trivy`        | https://github.com/orgs/aquasecurity/packages/container/package/trivy | Official       |
| AWS Elastic Container Registry (ECR) | `public.ecr.aws/aquasecurity/trivy` | https://gallery.ecr.aws/aquasecurity/trivy                            | Official       |

## Other Tools to use and deploy Trivy

For additional tools and ways to install and use Trivy in different environments such as in IDE, Kubernetes or CI/CD, see [Ecosystem section](../ecosystem/index.md).
