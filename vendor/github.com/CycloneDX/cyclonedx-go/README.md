# cyclonedx-go

[![Build Status](https://github.com/CycloneDX/cyclonedx-go/actions/workflows/ci.yml/badge.svg)](https://github.com/CycloneDX/cyclonedx-go/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/CycloneDX/cyclonedx-go)](https://goreportcard.com/report/github.com/CycloneDX/cyclonedx-go)
[![Go Reference](https://pkg.go.dev/badge/github.com/nscuro/cyclonedx-go.svg)](https://pkg.go.dev/github.com/CycloneDX/cyclonedx-go)
[![License](https://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](LICENSE)  
[![Website](https://img.shields.io/badge/https://-cyclonedx.org-blue.svg)](https://cyclonedx.org/)
[![Slack Invite](https://img.shields.io/badge/Slack-Join-blue?logo=slack&labelColor=393939)](https://cyclonedx.org/slack/invite)
[![Group Discussion](https://img.shields.io/badge/discussion-groups.io-blue.svg)](https://groups.io/g/CycloneDX)
[![Twitter](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Follow)](https://twitter.com/CycloneDX_Spec)

*cyclonedx-go is a Go library to consume and produce CycloneDX Software Bill of Materials (SBOM)*

> If you just want to create BOMs for your Go projects, see [*cyclonedx-gomod*](https://github.com/CycloneDX/cyclonedx-gomod)

## Installation

```
go get github.com/CycloneDX/cyclonedx-go
```

## Usage

Please refer to the module's [documentation](https://pkg.go.dev/github.com/CycloneDX/cyclonedx-go#section-documentation).  
Also, checkout the [`examples`](./example_test.go) to get an idea of how this library may be used.

## Compatibility

| cyclonedx-go versions | Supported Go versions | Supported CycloneDX spec |
|:---------------------:|:---------------------:|:------------------------:|
|    < v0.4.0           |         1.14+         |           1.2            |
|   == v0.4.0           |         1.14+         |           1.3            |
|   >= v0.5.0           |         1.15+         |           1.4            |

We're aiming to support all [officially supported](https://golang.org/doc/devel/release.html#policy) Go versions, plus
an additional older version.

This library will only support the latest version of the CycloneDX specification. While it's generally possible to 
*read* BOMs of an older spec, *writing* will exclusively produce BOMs conforming to the latest supported spec.

## Copyright & License

CycloneDX Go is Copyright (c) OWASP Foundation. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license.  
See the [LICENSE](./LICENSE) file for the full license.

## Contributing

[![Open in Gitpod](https://gitpod.io/button/open-in-gitpod.svg)](https://gitpod.io/#https://github.com/CycloneDX/cyclonedx-go)

Pull requests are welcome. But please read the
[CycloneDX contributing guidelines](https://github.com/CycloneDX/.github/blob/master/CONTRIBUTING.md) first.

It is generally expected that pull requests will include relevant tests. Tests are automatically run against all
supported Go versions (see [Compatibility](#compatibility)) for every pull request.

### Running Tests

Some tests make use of the [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli), e.g. to validate BOMs.  
Make sure to download the CLI binary and make it available as `cyclonedx` in your `$PATH`.  
This is done automatically for [Gitpod](https://gitpod.io/#https://github.com/CycloneDX/cyclonedx-go).