# Semaphore

- Here is a step-by-step tutorial on how to do [vulnerability testing with Semaphore CI/CD][tutorial].
- You can configure the pipeline visually or use the following YAML snippet to get started.

```
$ cat .semaphore/semaphore.yml
version: v1.0
name: CI pipeline
agent:
  machine:
    type: e1-standard-2
    os_image: ubuntu1804
blocks:
  - name: Security Test
    task:
      jobs:
        - name: Trivy code scan
          commands:
            - 'wget https://github.com/aquasecurity/trivy/releases/download/v0.20.1/trivy_0.20.1_Linux-64bit.deb'
            - sudo dpkg -i trivy_0.20.1_Linux-64bit.deb
            - checkout
            - trivy fs --exit-code 1 .
```

[tutorial]: https://semaphoreci.com/blog/continuous-container-vulnerability-testing-with-trivy
