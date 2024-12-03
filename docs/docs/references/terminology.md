# Terminology

This page explains the terminology system used in Trivy, helping users understand the specific terms and concepts unique to the Trivy ecosystem.

**Inclusion Criteria**

1. Core Components of Trivy
    - Primary features such as Scanner, Target
    - Essential components such as Scan Assets (trivy-db, trivy-java-db)
    - Components that users directly interact with

2. Trivy-specific Terms
    - Terms unique to Trivy (e.g., VEX Hub)
    - Terms that have special meaning in Trivy's context (e.g., Plugin, Module)

**Exclusion Criteria**

1. General Terms
    - Common security/technical terms (e.g., CVE, CVSS, Container, Registry)
    - Standard industry terminology

2. Implementation Details
    - Internal workings of components
    - Usage instructions (these belong in feature documentation)


## Core Concepts

### Target
Types of artifacts that Trivy can scan, like container images and filesystem.

### Scanner
Trivy's built-in security scanning engines. Trivy has four main scanners:

- [Vulnerability Scanner](../scanner/vulnerability.md)
- [Misconfiguration Scanner](../scanner/misconfiguration/index.md)
- [Secret Scanner](../scanner/secret.md)
- [License Scanner](../scanner/license.md)

!!! note
   SBOM is not a scanner but an output format option.

### Scan Assets
External data that Trivy downloads (if needed for scanner) and uses during scanning:

- [Vulnerability Database (Trivy DB, trivy-db)](#vulnerability-database-trivy-db-trivy-db): Database containing vulnerability information
- [Java Index Database (Trivy Java DB, trivy-java-db)](#java-index-database-trivy-java-db-trivy-java-db): Database for Java artifact identification
- [Checks Bundle (trivy-checks)](#checks-bundle): Archive containing misconfiguration detection rules
- [VEX Repository](#vex-repository): Repository containing VEX documents

## Vulnerability Scanning

### Vulnerability Database (Trivy DB, trivy-db)
The core vulnerability database required for vulnerability detection.
Contains comprehensive vulnerability information for multiple ecosystems.
Distributed via OCI registry.

Managed at https://github.com/aquasecurity/trivy-db.

The vulnerability database is built from a GitHub repository that collects and stores vulnerability information from various data sources.
This repository serves as the foundation for building the Trivy DB.

Managed at:

- https://github.com/aquasecurity/vuln-list
- https://github.com/aquasecurity/vuln-list-nvd
- https://github.com/aquasecurity/vuln-list-redhat
- https://github.com/aquasecurity/vuln-list-debian
- etc.

### Java Index Database (Trivy Java DB, trivy-java-db)
Specialized database used for identifying Java libraries and their components during JAR/WAR/PAR/EAR scanning.
Distributed via OCI registry.

Managed at https://github.com/aquasecurity/trivy-java-db.


## Misconfiguration Scanning
When the context does not clearly indicate these terms are related to misconfiguration scanning, they may be prefixed with "Misconfiguration" for clarity.
For example, "Check" may be referred to as "Misconfiguration Check", and "Checks Bundle" as "Misconfiguration Checks Bundle".

### Check
A Rego file that defines rules for detecting misconfigurations in various types of IaC files.

### Built-in Checks
Default set of checks distributed through [the trivy-checks repository](https://github.com/aquasecurity/trivy-checks), providing standard security and configuration best practices.

### Checks Bundle
A tar.gz archive containing [the built-in checks](#built-in-checks), distributed via OCI registry.

## Secret Scanning

### Rule
Pattern matching rules used to detect hardcoded secrets and sensitive information.
Each rule consists of:

- Metadata (ID, Category, Title, etc.)
- Regular expressions for matching sensitive patterns
- Additional context for detection accuracy

## Kubernetes Integration

### KBOM (Kubernetes Bill of Materials)
A specialized SBOM format for Kubernetes clusters that includes detailed information about the cluster's components.

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

### Cache Types
The cache directory contains several distinct types of data:

- [Vulnerability Database](#vulnerability-database-trivy-db-trivy-db)
- [Java Index Database](#java-index-database-trivy-java-db-trivy-java-db)
- [Misconfiguration Checks](#misconfiguration-scanning)
- [VEX Repositories](#vex-repository)
- [Scan Cache](#scan-cache)

### Asset Cache
Downloaded assets like vulnerability databases and Java index databases.

### Scan Cache
A caching mechanism that stores analysis results from previous scans to speed up subsequent scans.
For container image scanning, the scan cache stores analysis results including package names and versions per layer.

For detailed information about caching, see [the document](../configuration/cache.md).

## Plugin System

### Plugin
An add-on tool that integrates with Trivy to extend its core functionality.
Plugins can be written in any programming language and integrate seamlessly with Trivy CLI, appearing in Trivy help and subcommands.
They can be installed and removed independently without affecting the core Trivy installation.

For detailed information about plugins, see [the document](../plugin/index.md).

### Plugin Index (trivy-plugin-index)
A centralized registry that lists available Trivy plugins, managed at https://github.com/aquasecurity/trivy-plugin-index.
The index maintains a curated list of official and community plugins, providing metadata such as plugin names, descriptions, and maintainers.
It enables plugin discovery through the `trivy plugin search` command and facilitates automatic plugin installation and updates.

For detailed information about the plugin index, see [the document](../plugin/user-guide.md).

## Module System
### Module
A WebAssembly-based extension mechanism that allows custom scanning logic without modifying the Trivy binary.
Modules can modify scan results by analyzing files or post-processing results.

For detailed information about modules, see [the document](../advanced/modules.md).