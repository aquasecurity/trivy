package ec2

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
resource "aws_instance" "good_example" {
  ami = "ami-7f89a64f"
  instance_type = "t1.micro"

  root_block_device {
      encrypted = true
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    volume_size = 5
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = true
  }
}
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
resource "aws_instance" "bad_example" {
  ami = "ami-7f89a64f"
  instance_type = "t1.micro"

  root_block_device {
      encrypted = false
  }

  ebs_block_device {
    device_name = "/dev/sdg"
    volume_size = 5
    volume_type = "gp2"
    delete_on_termination = false
    encrypted = false
  }
}
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
