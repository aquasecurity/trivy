# Jenkins

An Jenkins Pipeline that generates and publishes trivy reports in HTML. See [trivy-jenkins][trivy-jenkins] for details.

```groovy
pipeline {
  agent any
  parameters {
    string(name: 'REGISTRY_NAME', defaultValue: '', description: 'Registry Name (Can be empty)')
    string(name: 'IMAGE_NAME', defaultValue: '', description: 'Image Name')
    string(name: 'IMAGE_TAG', defaultValue: '', description: 'Image Tag')
  }
  stages {
    stage('Scan Docker Image') {
      steps {
        script {
          def formatOption = "--format template --template \"@/usr/local/share/trivy/templates/html.tpl\""
          def imageFullName = null
          if (params.REGISTRY_NAME == '') {
            imageFullName = "$IMAGE_NAME:$IMAGE_TAG"
          } else {
            imageFullName = "$REGISTRY_NAME/$IMAGE_NAME:$IMAGE_TAG"
          }
          sh """
            trivy image $imageFullName $formatOption --timeout 10m --output report.html || true
          """
        }

        publishHTML(target: [
          allowMissing: true,
          alwaysLinkToLastBuild: false,
          keepAll: true,
          reportDir: ".",
          reportFiles: "report.html",
          reportName: "Trivy Report",
        ])
      }
    }
  }
}
```
Here's an example pipeline project:
![project](https://github.com/blueskyson/trivy-jenkins/blob/main/images/image1.png?raw=true)
Here's a report:
![report](https://github.com/blueskyson/trivy-jenkins/blob/main/images/image2.png?raw=true)

[trivy-jenkins]: https://github.com/blueskyson/trivy-jenkins