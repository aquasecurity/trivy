# Terminology

This page explains the terminology system used in Trivy, helping users understand the specific terms and concepts unique to the Trivy ecosystem.

## Core Concepts

### Target
Types of artifacts that Trivy can scan, like container images and filesystem.

### Scanner
Trivy's built-in security scanning engines. Trivy has four main scanners:

- [Vulnerability Scanner](../scanner/vulnerability.md): Detects known vulnerabilities in OS packages and application dependencies
- [Misconfiguration Scanner](../scanner/misconfiguration/index.md): Identifies security misconfigurations in IaC files
- [Secret Scanner](../scanner/secret.md): Finds hardcoded secrets and sensitive information
- [License Scanner](../scanner/license.md): Identifies software license issues

### Scan Assets
External data that Trivy downloads and uses during scanning:

- [Vulnerability Database (Trivy DB, trivy-db)](#vulnerability-database-trivy-db-trivy-db)   : Database containing vulnerability information
- [Java Index Database (Trivy Java DB, trivy-java-db)](#java-index-database-trivy-java-db-trivy-java-db): Database for Java artifact identification
- [Checks Bundle (trivy-checks)](#checks-bundle): Archive containing misconfiguration detection rules
- [VEX Repository](#vex-repository)

## Vulnerability Scanning

### Vulnerability Database (Trivy DB, trivy-db)
The core vulnerability database required for vulnerability detection.
Contains comprehensive vulnerability information for multiple ecosystems.
Distributed via OCI registry.

Managed at [the GitHub repository](https://github.com/aquasecurity/trivy-db).

### Java Index Database (Trivy Java DB, trivy-java-db)
Specialized database used for identifying Java libraries and their components during JAR/WAR/PAR/EAR scanning.
Distributed via OCI registry.

Managed at [the GitHub repository](https://github.com/aquasecurity/trivy-java-db).

### vuln-list
A GitHub repository that collects and stores vulnerability information from various data sources.
This repository serves as the foundation for building the Trivy DB.

Managed at:

- https://github.com/aquasecurity/vuln-list
- https://github.com/aquasecurity/vuln-list-nvd
- https://github.com/aquasecurity/vuln-list-redhat
- https://github.com/aquasecurity/vuln-list-debian
- etc.

## Misconfiguration Scanning

### Check
A Rego file that defines rules for detecting misconfigurations in various types of IaC files.

### Built-in Checks
Default set of checks distributed through [the trivy-checks repository](https://github.com/aquasecurity/trivy-checks), providing standard security and configuration best practices.

### Checks Bundle
A tar.gz archive containing [the built-in checks](#built-in-checks), distributed via OCI registry.

## Secret Scanning

### Rules
Pattern matching rules used to detect hardcoded secrets and sensitive information.
Each rule consists of:

- Metadata (ID, Category, Title, etc.)
- Regular expressions for matching sensitive patterns
- Additional context for detection accuracy

## License Scanning

### Standard Scanning
The default license scanning mode that focuses on package manager metadata.
Scans for licenses in package managers including:

- OS packages: apk, apt-get, dnf, etc.
- Language packages: npm, pip, gem, etc.

### Full Scanning
An extended scanning mode activated with `--license-full` flag.
Performs comprehensive license detection across the entire codebase, including:

- Source code files
- Markdown documents
- Text files
- LICENSE files

### Confidence Level
A threshold value that determines the reliability of license detection.
Higher values increase detection accuracy but may miss some licenses, while lower values catch more potential licenses but may include false positives.

## Kubernetes Integration

### Trivy Operator
Kubernetes operator for Trivy that enables continuous security scanning in Kubernetes clusters.
The operator automates vulnerability and misconfiguration scanning of workloads running in a cluster.

Managed at https://github.com/aquasecurity/trivy-operator.

### KBOM (Kubernetes Bill of Materials)
A specialized SBOM format for Kubernetes clusters that includes:

- Control plane component versions
- Node component versions
- Add-on versions and configurations
- Complete cluster component inventory

## VEX (Vulnerability Exploitability eXchange)

### VEX Repository
A repository system that stores VEX documents following [the VEX Repository Specification](https://github.com/aquasecurity/vex-repo-spec).
VEX repositories help users manage and share information about vulnerability applicability and exploitability.

For detailed information about VEX repositories, see [the document](../supply-chain/vex/repo.md).

### VEX Hub
The default VEX repository managed by Aqua Security at https://github.com/aquasecurity/vexhub.
It primarily aggregates VEX documents published by package maintainers in their source repositories.
VEX Hub serves as a central point for collecting and distributing vulnerability applicability information for OSS projects.

## Cache System

### Cache Directory
A storage location that contains various types of cache data used by Trivy.
The default location follows the XDG specification, but can be customized using the `--cache-dir` flag.
This directory manages multiple types of cached data essential for Trivy's operation.

### Cache Types
The cache directory contains several distinct types of data:

- [Vulnerability Database](#vulnerability-database-trivy-db-trivy-db)
- [Java Index Database](#java-index-database-trivy-java-db-trivy-java-db)
- [Misconfiguration Checks](#misconfiguration-scanning)
- [VEX Repositories](#vex-repository)
- [Scan Cache](#scan-cache)

### Scan Cache
A caching mechanism that stores analysis results from previous scans to speed up subsequent scans.
For container image scanning, the scan cache stores analysis results including package names and versions per layer.

For detailed information about caching, see [Cache](../configuration/cache.md).

## Plugin System

### Plugin
An add-on tool that integrates with Trivy to extend its core functionality.
Plugins can be written in any programming language and integrate seamlessly with Trivy CLI, appearing in Trivy help and subcommands.
They can be installed and removed independently without affecting the core Trivy installation.

For detailed information about plugins, see [the document](../plugin/index.md).

### Plugin Index
A centralized registry that lists available Trivy plugins, managed at https://github.com/aquasecurity/trivy-plugin-index.
The index maintains a curated list of official and community plugins, providing metadata such as plugin names, descriptions, and maintainers.
It enables plugin discovery through the `trivy plugin search` command and facilitates automatic plugin installation and updates.

For detailed information about the plugin index, see [the document](../plugin/user-guide.md).

### Output Plugin
A special type of plugin that can process Trivy's output data.
These plugins can transform scan results into different formats or forward them to external systems.
They receive data via standard input and can be invoked as part of Trivy's built-in commands.

## Module System

### Module
A WebAssembly-based extension mechanism that allows custom scanning logic without modifying the Trivy binary.
Modules can modify scan results by analyzing files or post-processing results.

For detailed information about modules, see [the document](../advanced/modules.md).

### Module Types
Two types of modules can be implemented:

- Analyzer: Examines specific files during scanning
- PostScanner: Processes and modifies scan results after scanning