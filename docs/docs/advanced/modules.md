# Modules

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

Trivy provides a module feature to allow others to extend the Trivy CLI without the need to change the Trivy code base.
It changes the behavior during scanning by WebAssembly.

## Overview
Trivy modules are add-on tools that integrate seamlessly with Trivy.
They provide a way to extend the core feature set of Trivy, but without updating the Trivy binary.

- They can be added and removed from a Trivy installation without impacting the core Trivy tool.
- They can be written in any programming language supporting WebAssembly.
  - It supports only [TinyGo][tinygo] at the moment.

You can write your own detection logic.

- Evaluate complex vulnerability conditions like [Spring4Shell][spring4shell]
- Detect a shell script communicating with malicious domains
- Detect malicious python install script (setup.py)
- Even detect misconfigurations in WordPress setting
- etc.

Then, you can update the scan result however you want.

- Change a severity
- Remove a vulnerability
- Add a new vulnerability
- etc.

Modules should be distributed in OCI registries like GitHub Container Registry.

!!! warning
    Trivy modules available in public are not audited for security.
    You should install and run third-party modules at your own risk even though WebAssembly is sandboxed.

Under the hood Trivy leverages [wazero][wazero] to run WebAssembly modules without any dependencies.

## Installing a Module
A module can be installed using the `trivy module install` command.
This command takes an url. It will download the module and install it in the module cache.

Trivy adheres to the XDG specification, so the location depends on whether XDG_DATA_HOME is set.
Trivy will now search XDG_DATA_HOME for the location of the Trivy modules cache.
The preference order is as follows:

- XDG_DATA_HOME if set and .trivy/plugins exists within the XDG_DATA_HOME dir
- $HOME/.trivy/plugins

For example, to download the WebAssembly module, you can execute the following command:

```bash
$ trivy module install ghcr.io/aquasecurity/trivy-module-spring4shell
```

## Using Modules
Once the module is installed, Trivy will load all available modules in the cache on the start of the next Trivy execution.
The modules may inject custom logic into scanning and change the result.

You will see the log messages about WASM modules.

```shell
2022-06-12T12:57:13.210+0300    INFO    Loading ghcr.io/aquasecurity/trivy-module-spring4shell/spring4shell.wasm...
2022-06-12T12:57:13.596+0300    INFO    Registering WASM module: spring4shell@v1
...
2022-06-12T12:57:14.865+0300    INFO    Module spring4shell: Java Version: 8, Tomcat Version: 8.5.77
2022-06-12T12:57:14.865+0300    INFO    Module spring4shell: change CVE-2022-22965 severity from CRITICAL to LOW
```

In the above example, the Spring4Shell module changed the severity from CRITICAL to LOW because the application doesn't satisfy one of conditions.


## Uninstalling Modules
Specify a module repository with `trivy module uninstall` command.

```bash
$ trivy module uninstall ghcr.io/aquasecurity/trivy-module-spring4shell
```

## Building Modules
It supports TinyGo only at the moment.

### TinyGo
Trivy provides Go SDK including three interfaces.
Your own module needs to implement either or both `Analyzer` and `PostScanner` in addition to `Module`.

```go
type Module interface {
    Version() int
    Name() string
}

type Analyzer interface {
    RequiredFiles() []string
    Analyze(filePath string) (*serialize.AnalysisResult, error)
}

type PostScanner interface {
    PostScanSpec() serialize.PostScanSpec
    PostScan(serialize.Results) (serialize.Results, error)
}
```

In the following tutorial, it creates a WordPress module that detects a WordPress version and a critical vulnerability accordingly.

!!! tips
    You can use logging functions such as `Debug` and `Info` for debugging.
    See [examples](#examples) for the detail.

#### Module interface
`Version()` returns your module version and should be incremented after updates.
`Name()` returns your module name.

```go
package main

const (
    version = 1
    name = "wordpress-module"
)

type WordpressModule struct{}

func (WordpressModule) Version() int {
    return version
}

func (WordpressModule) Name() string {
    return name
}
```

#### Analyzer interface
If you implement the `Analyzer` interface, `Analyze` method is called when the file path is matched to file patterns returned by `RequiredFiles()`.
`Analyze` takes the matched file path, then the file can be opened by `os.Open()`.

```go
const typeWPVersion = "wordpress-version"

func (WordpressModule) RequiredFiles() []string {
    return []string{
        `wp-includes\/version.php`,
    }
}

func (WordpressModule) Analyze(filePath string) (*serialize.AnalysisResult, error) {
    f, err := os.Open(filePath) // e.g. filePath: /usr/src/wordpress/wp-includes/version.php
    if err != nil {
        return nil, err
    }
    defer f.Close()

    var wpVersion string
    scanner := bufio.NewScanner(f)
    for scanner.Scan() {
        line := scanner.Text()
        if !strings.HasPrefix(line, "$wp_version=") {
            continue
        }

        ss := strings.Split(line, "=")
        if len(ss) != 2 {
            return nil, fmt.Errorf("invalid wordpress version: %s", line)
        }

        // NOTE: it is an example; you actually need to handle comments, etc
        ss[1] = strings.TrimSpace(ss[1])
        wpVersion = strings.Trim(ss[1], `";`)
    }

    if err = scanner.Err(); err != nil {
        return nil, err
    }
	
    return &serialize.AnalysisResult{
        CustomResources: []serialize.CustomResource{
            {
                Type:     typeWPVersion,
                FilePath: filePath,
                Data:     wpVersion,
            },
        },
    }, nil
}
```

!!! tips
    Trivy caches analysis results according to the module version.
    We'd recommend cleaning the cache or changing the module version every time you update `Analyzer`.


#### PostScanner interface
`PostScan` is called after scanning and takes the scan result as an argument from Trivy.
In post scanning, your module can perform one of three actions:

- Insert
    - Add a new security finding
    - e.g. Add a new vulnerability and misconfiguration
- Update
    - Update the detected vulnerability and misconfiguration
    - e.g. Change a severity
- Delete
    - Update the detected vulnerability and misconfiguration
    - e.g. Remove Spring4Shell because it is not actually affected.
 
`PostScanSpec()` returns which action the module does.
If it is `Update` or `Delete`, it also needs to return IDs such as CVE-ID and misconfiguration ID, which your module wants to update or delete.

`serialize.Results` contains the filtered results matching IDs you specified.
Also, it includes `CustomResources` with the values your `Analyze` returns, so you can modify the scan result according to the custom resources.

```go
func (WordpressModule) PostScanSpec() serialize.PostScanSpec {
    return serialize.PostScanSpec{
        Action: api.ActionInsert, // Add new vulnerabilities
    }
}

func (WordpressModule) PostScan(results serialize.Results) (serialize.Results, error) {
    // e.g. results
    // [
    //   {
    //     "Target": "",
    //     "Class": "custom",
    //     "CustomResources": [
    //       {
    //         "Type": "wordpress-version",
    //         "FilePath": "/usr/src/wordpress/wp-includes/version.php",
    //         "Layer": {
    //           "DiffID": "sha256:057649e61046e02c975b84557c03c6cca095b8c9accd3bd20eb4e432f7aec887"
    //         },
    //         "Data": "5.7.1"
    //       }
    //     ]
    //   }
    // ]   
    var wpVersion int
    for _, result := range results {
        if result.Class != types.ClassCustom {
            continue
        }
		
        for _, c := range result.CustomResources {
            if c.Type != typeWPVersion {
                continue
            }
            wpVersion = c.Data.(string)
            wasm.Info(fmt.Sprintf("WordPress Version: %s", wpVersion))

            ...snip...
			
            if affectedVersion.Check(ver) {
                vulnerable = true
            }
            break
        }
    }

    if vulnerable {
        // Add CVE-2020-36326
        results = append(results, serialize.Result{
            Target: wpPath,
            Class:  types.ClassLangPkg,
			Type:   "wordpress",
            Vulnerabilities: []types.DetectedVulnerability {
                {
                    VulnerabilityID:  "CVE-2020-36326",
                    PkgName:          "wordpress",
                    InstalledVersion: wpVersion,
                    FixedVersion:     "5.7.2",
                    Vulnerability: dbTypes.Vulnerability{
                        Title:    "PHPMailer 6.1.8 through 6.4.0 allows object injection through Phar Deserialization via addAttachment with a UNC pathname.",
                        Severity: "CRITICAL",
                    },
                },
            },
        })
    }
    return results, nil
}
```

The new vulnerability will be added to the scan results.
This example shows how the module inserts a new finding.
If you are interested in `Update`, you can see an example of [Spring4Shell][trivy-module-spring4shell].

#### Build
Follow [the install guide][tinygo-installation] and install TinyGo.

```bash
$ tinygo build -o wordpress.wasm -scheduler=none -target=wasi --no-debug wordpress.go
```

Put the built binary to the module directory that is under the home directory by default.

```bash
$ mkdir -p ~/.trivy/modules
$ cp spring4shell.wasm ~/.trivy/modules
```

## Distribute Your Module
You can distribute your own module in OCI registries. Please follow [the oras installation instruction][oras].

```bash
oras push ghcr.io/aquasecurity/trivy-module-wordpress:latest wordpress.wasm:application/vnd.module.wasm.content.layer.v1+wasm
Uploading 3daa3dac086b wordpress.wasm
Pushed ghcr.io/aquasecurity/trivy-module-wordpress:latest
Digest: sha256:6416d0199d66ce52ced19f01d75454b22692ff3aa7737e45f7a189880840424f
```

## Examples
- [Spring4Shell][trivy-module-spring4shell]
- [WordPress][trivy-module-wordpress]


[tinygo]: https://tinygo.org/
[spring4shell]: https://blog.aquasec.com/zero-day-rce-vulnerability-spring4shell
[wazero]: https://github.com/tetratelabs/wazero

[trivy-module-spring4shell]: https://github.com/aquasecurity/trivy/tree/main/examples/module/spring4shell
[trivy-module-wordpress]: https://github.com/aquasecurity/trivy/tree/main/examples/module/wordpress

[tinygo-installation]: https://tinygo.org/getting-started/install/
[oras]: https://oras.land/cli/