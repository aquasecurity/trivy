With Jenkins it is possible to do scriped pipelines but also declaative pipelines. I prefere declarative pipelines. You will find more information about pipelines in jenkins at https://www.jenkins.io/doc/book/pipeline/.

The result parser is inlcuded in an existing plugn called Warning NG (https://plugins.jenkins.io/warnings-ng/).

Ensure that the plugin is installed, than you need to execute the he scan in the shell
```
sh "trivy image -f json -o results.json aquasec/trivy:0.19.2"
```
Now you cold collect the resuls immediatly or doing this in a pos section on the stage or a post section at the end of he pipeline.
```
recordIssues(tools: [trivy(pattern: 'results.json')])
```

A simple example of a declarative pipeline in a kubernetes envionment:
```
// Uses Declarative syntax to run commands inside a container.
pipeline {
    agent {
        // use an agent with trivy installed 
        // or pull it in a stage 
        // or use a ON-DEMAND agent in kubernetes by using the known oci image
        kubernetes {
            // Rather than inline YAML, in a multibranch Pipeline you could use: yamlFile 'jenkins-pod.yaml'
            // Or, to avoid YAML:
            containerTemplate {
                 name 'trivy'
                 image 'aquasec/trivy:0.19.2'
                 command 'sleep'
                 args 'infinity'
            }
        }
    }
    stages {
        stage('build image') {
            steps {
                echo "build your image as you want here."
            }
        }
        
        stage('scan with trivy') {
            steps {
                sh "trivy image -f json -o results.json aquasec/trivy:0.19.2"
                recordIssues(tools: [trivy(pattern: 'results.json')])
            }
        }
    }
}
```
