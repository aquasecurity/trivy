package config.type

test_detect_kubernetes {
    result := detect with input as {
        "apiVersion": "apps/v1",
        "kind": "Pod",
        "metadata": {
            "name": "test"
        },
        "spec": {
            "containers": {
                "name": "nginx",
                "image": "nginx:1.14.2",
            }
        }
    }
    result[_] == "kubernetes"
}

test_detect_non_kubernetes{
    result := detect with input as {
        "apiVersion": "apps/v1",
        "kind": "Pod",
        "metadata": {
            "name": "test"
        },
    }
    count({x | result[x] == "kubernetes"}) == 0
}

test_detect_cloudformation {
    result := detect with input as {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Description": "A sample template",
        "Resources": {
            "MyEC2Instance": {
                "Type": "AWS::EC2::Instance"
            }
        }
    }
    result[_] == "cloudformation"
}

test_detect_non_cloudformation {
    result := detect with input as {
        "TemplateFormatVersion": "2010-09-09",
        "Description": "A sample template",
        "Resources": {
            "MyEC2Instance": {
                "Type": "AWS::EC2::Instance"
            }
        }
    }
    count({x | result[x] == "cloudformation"}) == 0
}

test_detect_ansible {
    result := detect with input as [
        {
            "name": "test",
            "hosts": "all",
            "tasks": [
                {"name": "install dependencies"},
                {"name": "setup"}
            ]
        },
        {
            "name": "test2",
            "hosts": "web",
            "tasks": [
                {"name": "install dependencies"},
                {"name": "setup"}
            ]
        }
    ]
    result[_] == "ansible"
}

test_detect_non_ansible {
    result := detect with input as [
        {
            "name": "test",
            "hosts": "all",
            "tasks": [
                {"name": "install dependencies"},
                {"name": "setup"}
            ]
        },
        {
            "name": "test2"
        }
    ]
    count({x | result[x] == "ansible"}) == 0
}
