module "endpoints" {
  source = "terraform-aws-modules/vpc/aws//modules/vpc-endpoints"
  version = "6.0.1"

  create                = true
  create_security_group = true
  vpc_id                = "vpc-12345678"

  endpoints = {
    s3 = {
      service = "s3"
    }
  }

  security_group_rules = [{
    description = ""
    type = "egress"
    cidr_blocks = ["0.0.0.0/0"]
  }]
}
