data "aws_ami" "this" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "architecture"
    values = ["arm64"]
  }
  filter {
    name   = "name"
    values = ["al2023-ami-2023*"]
  }
}

resource "aws_instance" "this" {
  ami = data.aws_ami.this.id
  instance_market_options {
    spot_options {
      max_price = 0.0031
    }
  }
  instance_type = var.instance_type
  tags = {
    Name = "test-spot"
  }
  user_data = var.user_data
}

variable "instance_type" {
  type = string
}

variable "user_data" {
  type = string
}