[Octant][octant] is a tool for developers to understand how applications run on a Kubernetes cluster. It aims to be part
of the developer's toolkit for gaining insight and approaching complexity found in Kubernetes. Octant offers a combination
of introspective tooling, cluster navigation, and object management along with a plugin system to further extend its
capabilities.

[Starboard Octant Plugin][octant-plugin] provides visibility into vulnerability assessment reports for Kubernetes workloads stored
as custom resources.

## Installation

### Prerequisites

- Octant >= 0.13 should first be installed. On macOS this is as simple as `brew install octant`. For installation
  instructions on other operating systems and package managers, see [Octant Installation][octant-installation].
- Environment authenticated against your Kubernetes cluster

!!! tip
    In the following instructions we assume that the `$HOME/.config/octant/plugins` directory is the default plugins
    location respected by Octant. Note that the default location might be changed by setting the `OCTANT_PLUGIN_PATH`
    environment variable when running Octant.

### From the Binary Releases

Every [release][release] of Starboard Octant Plugin provides binary releases for a variety of operating systems. These
binary versions can be manually downloaded and installed.

1. Download your [desired version][release]
2. Unpack it (`tar -zxvf starboard-octant-plugin_darwin_x86_64.tar`)
3. Find the `starboard-octant-plugin` binary in the unpacked directory, and move it to the default Octant's
   configuration directory (`mv starboard-octant-plugin_darwin_x86_64/starboard-octant-plugin $HOME/.config/octant/plugins`).
   You might need to create the directory if it doesn't exist already.

### From Source (Linux, macOS)

Building from source is slightly more work, but is the best way to go if you want to test the latest (pre-release)
version of the plugin.

You must have a working Go environment.

```
git clone git@github.com:aquasecurity/starboard-octant-plugin.git
cd starboard-octant-plugin
make install
```

The `make install` goal copies the plugin binary to the `$HOME/.config/octant/plugins` directory.

## Uninstall

Run the following command to remove the plugin:

```
rm -f $OCTANT_PLUGIN_PATH/starboard-octant-plugin
```

where `$OCTANT_PLUGIN_PATH` is the default plugins location respected by Octant. If not set, it defaults to the
`$HOME/.config/octant/plugins` directory.

[octant]: https://octant.dev/
[octant-plugin]: https://github.com/aquasecurity/starboard-octant-plugin
[octant-installation]: https://github.com/vmware-tanzu/octant#installation
[release]: https://github.com/aquasecurity/starboard-octant-plugin/releases
