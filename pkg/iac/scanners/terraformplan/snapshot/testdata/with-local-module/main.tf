module "ec2_instance" {
  source = "./modules/ec2"
  instance_type = "t3.micro"
  user_data = "test"
}