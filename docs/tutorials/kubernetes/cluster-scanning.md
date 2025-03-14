# Kubernetes Scanning Tutorial

## Prerequisites

To test the following commands yourself, make sure that you’re connected to a Kubernetes cluster. A simple kind, a Docker-Desktop or microk8s cluster will do. In our case, we’ll use a one-node kind cluster.  
Pro tip: The output of the commands will be even more interesting if you have some workloads running in your cluster.

## Cluster Scanning

Trivy K8s is great to get an overview of all the vulnerabilities and misconfiguration issues or to scan specific workloads that are running in your cluster. You would want to use the Trivy K8s command either on your own local cluster or in your CI/CD pipeline post deployments.  

The `trivy k8s` command is part of the Trivy CLI.

With the following command, we can scan our entire Kubernetes cluster for vulnerabilities and get a summary of the scan:

```sh
trivy k8s --report=summary
```

To get detailed information for all your resources, just replace ‘summary’ with ‘all’: 

```sh
trivy k8s --report=all
```

However, we recommend displaying all information only in case you scan a specific namespace or resource since you can get overwhelmed with additional details. 

Furthermore, we can specify the namespace that Trivy is supposed to scan to focus on specific resources in the scan result: 

```sh
trivy k8s --include-namespaces kube-system --report summary
```

Again, if you’d like to receive additional details, use the ‘--report=all’ flag: 

```sh
trivy k8s --include-namespaces kube-system --report all
```

Like with scanning for vulnerabilities, we can also filter in-cluster security issues by severity of the vulnerabilities: 

```sh
trivy k8s --severity=CRITICAL --report=summary
```

Note that you can use any of the Trivy flags on the Trivy K8s command. 

## Trivy Operator

The Trivy K8s command is an imperative model to scan resources. We wouldn’t want to manually scan each resource across different environments. The larger the cluster and the more workloads are running in it, the more error-prone this process would become. With the Trivy Operator, we can automate the scanning process after the deployment.  

The Trivy Operator follows the Kubernetes Operator Model. Operators automate human actions, and the result of the task is saved as custom resource definitions (CRDs) within your cluster. 

This has several benefits: 

- Trivy Operator is installed CRDs in our cluster. As a result, all our resources, including our security scanner and its scan results, are Kubernetes resources. This makes it much easier to integrate the Trivy Operator directly into our existing processes, such as connecting Trivy with Prometheus, a monitoring system. 

- The Trivy Operator will automatically scan your resources every six hours. You can set up automatic alerting in case new critical security issues are discovered. 

- The CRDs can be both machine and human-readable depending on which applications consume the CRDs. This allows for more versatile applications of the Trivy operator. 

There are several ways that you can install the Trivy Operator in your cluster. In this guide, we’re going to use the Helm installation.

Please follow the Trivy Operator documentation for further information on:

- [Installation of the Trivy Operator](https://aquasecurity.github.io/trivy-operator/latest/getting-started/installation/)
- [Getting started guide](https://aquasecurity.github.io/trivy-operator/latest/getting-started/quick-start/)