# Trivy Project Governance
This document outlines the guiding principles and governance framework for the Trivy project.

## Core Principles
Trivy is a security scanner focused on static analysis and designed with simplicity and security at its core.
All new proposals to the project must adhere to the following principles.

### Static Analysis (No Runtime Required)
Trivy operates without requiring container or VM image startups, eliminating the need for Docker or similar runtimes, except for scanning images stored within a container runtime.
This approach enhances security and efficiency by minimizing dependencies.

### External Dependency Free (Single Binary)
Operating as a single binary, Trivy is independent of external environments and avoids executing external OS commands (e.g. Maven or RPM) or processes.
If specific functionality, like Maven's, is needed, Trivy opts for internal reimplementations or processing outputs of the tool without direct execution of external tools.

### Security Focus
Trivy prioritizes the identification of security issues, excluding features unrelated to security, such as performance metrics or content listings of container images.
It can, however, produce and output intermediate representations like SBOMs for comprehensive security assessments.

### Detecting Unintended States
Trivy is designed to detect unintended vulnerable states in projects, such as the use of vulnerable versions of dependencies or misconfigurations in Infrastructure as Code (IaC) that may unintentionally expose servers to the internet.
The focus is on identifying developer mistakes or undesirable states, not on detecting intentional attacks, such as malicious images and malware.

## Governance Model
The governance of Trivy is collaborative, valuing community input while recognizing Aqua Security's role in making final decisions.
This model ensures that decisions, proposals, and enhancements align with Trivy's mission to provide a secure, simple, and independent security scanning solution, adhering to the project's core principles.