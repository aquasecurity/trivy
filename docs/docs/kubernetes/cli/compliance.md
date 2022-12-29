# Kubernetes Compliance

!!! warning "EXPERIMENTAL"
    This feature might change without preserving backwards compatibility.

This page describes Kubernetes specific compliance reports. For an overview of Trivy's Compliance feature, including working with custom compliance, check out the [Compliance documentation](../../compliance/compliance.md).

## Built in reports

The following reports are available out of the box:

| Compliance | Name for command | More info
--- | --- | ---
NSA, CISA Kubernetes Hardening Guidance v1.2 | `k8s-nsa` | [Link](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
CIS Benchmark for Kubernetes v1.23 | `k8s-cis` | [Link](https://www.cisecurity.org/benchmark/kubernetes)

## Examples

Scan a full cluster and generate a compliance summary report:

```
$ trivy k8s cluster --compliance=<compliance_id> --report summary
```

***Note*** : The `Issues` column represent the total number of failed checks for this control.


Get all of the detailed output for checks:

```
trivy k8s cluster --compliance=<compliance_id> --report all
```

Report result in JSON format:

```
trivy k8s cluster --compliance=<compliance_id> --report summary --format json
```

```
trivy k8s cluster --compliance=<compliance_id> --report all --format json
```
